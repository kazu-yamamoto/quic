{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Crypto.Nite (
    niteEncrypt
  , niteEncrypt'
  , niteDecrypt
  , niteDecrypt'
  , protectionMask
  , aes128gcmEncrypt
  , makeNonce
  , NiteEncrypt(..)
  , initialNiteEncrypt
  , NiteDecrypt(..)
  , initialNiteDecrypt
  ) where

import Crypto.Cipher.AES
import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly
import Crypto.Cipher.Types hiding (Cipher, IV)
import Crypto.Error (throwCryptoError, maybeCryptoError)
import qualified Crypto.MAC.Poly1305 as Poly1305
import qualified Data.ByteArray as Byte (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (peek, poke)
import Network.TLS hiding (Version)
import Network.TLS.Extra.Cipher

import Network.QUIC.Crypto.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

-- It would be nice to take [PlainText] and update AEAD context with
-- [PlainText]. But since each PlainText is not aligned to cipher block,
-- it's impossible.
cipherEncrypt :: Cipher -> Key -> Nonce -> PlainText -> AssDat -> (CipherText,CipherText)
cipherEncrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmEncrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = error "cipher_TLS13_AES128CCM_SHA256"
  | cipher == cipher_TLS13_AES256GCM_SHA384        = aes256gcmEncrypt
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = chacha20poly1305Encrypt
  | otherwise                                      = error "cipherEncrypt"

cipherDecrypt :: Cipher -> Key -> Nonce -> CipherText -> AssDat -> Maybe PlainText
cipherDecrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmDecrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = error "cipher_TLS13_AES128CCM_SHA256"
  | cipher == cipher_TLS13_AES256GCM_SHA384        = aes256gcmDecrypt
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = chacha20poly1305Decrypt
  | otherwise                                      = error "cipherDecrypt"

-- IMPORTANT: Using 'let' so that parameters can be memorized.
aes128gcmEncrypt :: Key -> (Nonce -> PlainText -> AssDat -> (CipherText,CipherText))
aes128gcmEncrypt (Key key) =
    let aes = throwCryptoError (cipherInit key) :: AES128
    in \(Nonce nonce) plaintext (AssDat ad) ->
      let aead = throwCryptoError $ aeadInit AEAD_GCM aes nonce
          (AuthTag tag0, ciphertext) = aeadSimpleEncrypt aead ad plaintext 16
          tag = Byte.convert tag0
      in (ciphertext,tag)

aes128gcmDecrypt :: Key -> (Nonce -> CipherText -> AssDat -> Maybe PlainText)
aes128gcmDecrypt (Key key) =
    let aes = throwCryptoError (cipherInit key) :: AES128
    in \(Nonce nonce) ciphertag (AssDat ad) ->
      let aead = throwCryptoError $ aeadInit AEAD_GCM aes nonce
          (ciphertext, tag) = BS.splitAt (BS.length ciphertag - 16) ciphertag
          authtag = AuthTag $ Byte.convert tag
       in aeadSimpleDecrypt aead ad ciphertext authtag

aes256gcmEncrypt :: Key -> (Nonce -> PlainText -> AssDat -> (CipherText,CipherText))
aes256gcmEncrypt (Key key) =
    let aes = throwCryptoError (cipherInit key) :: AES256
    in \(Nonce nonce) plaintext (AssDat ad) ->
      let aead = throwCryptoError $ aeadInit AEAD_GCM aes nonce
          (AuthTag tag0, ciphertext) = aeadSimpleEncrypt aead ad plaintext 16
          tag = Byte.convert tag0
      in (ciphertext,tag)

aes256gcmDecrypt :: Key -> (Nonce -> CipherText -> AssDat -> Maybe PlainText)
aes256gcmDecrypt (Key key) =
    let aes = throwCryptoError (cipherInit key) :: AES256
    in \(Nonce nonce) ciphertag (AssDat ad) ->
      let aead = throwCryptoError $ aeadInit AEAD_GCM aes nonce
          (ciphertext, tag) = BS.splitAt (BS.length ciphertag - 16) ciphertag
          authtag = AuthTag $ Byte.convert tag
      in aeadSimpleDecrypt aead ad ciphertext authtag

chacha20poly1305Encrypt :: Key -> Nonce -> PlainText -> AssDat -> (CipherText,CipherText)
chacha20poly1305Encrypt (Key key) (Nonce nonce) plaintext (AssDat ad) =
    (ciphertext,Byte.convert tag)
  where
    st1 = throwCryptoError (ChaChaPoly.nonce12 nonce >>= ChaChaPoly.initialize key)
    st2 = ChaChaPoly.finalizeAAD (ChaChaPoly.appendAAD ad st1)
    (ciphertext, st3) = ChaChaPoly.encrypt plaintext st2
    Poly1305.Auth tag = ChaChaPoly.finalize st3

chacha20poly1305Decrypt :: Key -> Nonce -> CipherText -> AssDat -> Maybe PlainText
chacha20poly1305Decrypt (Key key) (Nonce nonce) ciphertag (AssDat ad) = do
    st <- maybeCryptoError (ChaChaPoly.nonce12 nonce >>= ChaChaPoly.initialize key)
    let st2 = ChaChaPoly.finalizeAAD (ChaChaPoly.appendAAD ad st)
        (ciphertext, tag) = BS.splitAt (BS.length ciphertag - 16) ciphertag
        (plaintext, st3) = ChaChaPoly.decrypt ciphertext st2
        Poly1305.Auth tag' = ChaChaPoly.finalize st3
    if tag == Byte.convert tag' then Just plaintext else Nothing

----------------------------------------------------------------

makeNonce :: IV -> ByteString -> Nonce
makeNonce (IV iv) pn = Nonce nonce
  where
    nonce = bsXORpad iv pn

-- XORing IV and a packet numbr with left padded.
--             src0
-- IV          +IIIIIIIIIIIIIIIIII--------+
--                 diff          src1
-- PN          +000000000000000000+-------+
--             dst
-- Nonce       +IIIIIIIIIIIIIIIIII--------+
bsXORpad :: ByteString -> ByteString -> ByteString
bsXORpad (PS fp0 off0 len0) (PS fp1 off1 len1)
  | len0 < len1 = error "bsXORpad"
  | otherwise = BS.unsafeCreate len0 $ \dst ->
  withForeignPtr fp0 $ \p0 ->
    withForeignPtr fp1 $ \p1 -> do
        let src0 = p0 `plusPtr` off0
        let src1 = p1 `plusPtr` off1
        let diff = len0 - len1
        BS.memcpy dst src0 diff
        loop (dst `plusPtr` diff) (src0 `plusPtr` diff) src1 len1
  where
    loop :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> IO ()
    loop _ _ _ 0 = return ()
    loop dst src0 src1 len = do
        w1 <- peek src0
        w2 <- peek src1
        poke dst (w1 `xor` w2)
        loop (dst `plusPtr` 1) (src0 `plusPtr` 1) (src1 `plusPtr` 1) (len - 1)

{-
bsXORpad' :: ByteString -> ByteString -> ByteString
bsXORpad' iv pn = BS.pack $ zipWith xor ivl pnl
  where
    ivl = BS.unpack iv
    diff = BS.length iv - BS.length pn
    pnl = replicate diff 0 ++ BS.unpack pn
-}

----------------------------------------------------------------

type NiteEnc = PlainText -> AssDat -> PacketNumber -> (CipherText,CipherText)

data NiteEncrypt = NiteEncrypt NiteEnc

initialNiteEncrypt :: NiteEncrypt
initialNiteEncrypt = NiteEncrypt $ \_ _ _ -> ("","")

niteEncrypt :: Cipher -> Key -> IV -> NiteEnc
niteEncrypt cipher key iv =
    let enc = cipherEncrypt cipher key
        mk  = makeNonce iv
    in \plaintext header pn -> let bytePN = bytestring64 $ fromIntegral pn
                                   nonce  = mk bytePN
                               in enc nonce plaintext header

niteEncrypt' :: Cipher -> Key -> Nonce -> PlainText -> AssDat -> (CipherText,CipherText)
niteEncrypt' cipher key nonce plaintext header =
    cipherEncrypt cipher key nonce plaintext header

----------------------------------------------------------------

type NiteDec = CipherText -> AssDat -> PacketNumber -> Maybe PlainText

data NiteDecrypt = NiteDecrypt NiteDec

initialNiteDecrypt :: NiteDecrypt
initialNiteDecrypt = NiteDecrypt $ \_ _ _ -> Nothing

niteDecrypt :: Cipher -> Key -> IV -> NiteDec
niteDecrypt cipher key iv =
    let dec = cipherDecrypt cipher key
        mk  = makeNonce iv
    in \ciphertext header pn -> let bytePN = bytestring64 (fromIntegral pn)
                                    nonce = mk bytePN
                                in dec nonce ciphertext header

niteDecrypt' :: Cipher -> Key -> Nonce -> CipherText -> AssDat -> Maybe PlainText
niteDecrypt' cipher key nonce ciphertext header =
    cipherDecrypt cipher key nonce ciphertext header

----------------------------------------------------------------

protectionMask :: Cipher -> Key -> (Sample -> Mask)
protectionMask cipher key =
    let f = cipherHeaderProtection cipher key
    in \sample -> f sample

cipherHeaderProtection :: Cipher -> Key -> (Sample -> Mask)
cipherHeaderProtection cipher key
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128ecbEncrypt key
  | cipher == cipher_TLS13_AES128CCM_SHA256        = error "cipher_TLS13_AES128CCM_SHA256"
  | cipher == cipher_TLS13_AES256GCM_SHA384        = aes256ecbEncrypt key
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = chachaEncrypt key
  | otherwise                                      = error "cipherHeaderProtection"

aes128ecbEncrypt :: Key -> (Sample -> Mask)
aes128ecbEncrypt (Key key) =
    let encrypt = ecbEncrypt (throwCryptoError (cipherInit key) :: AES128)
    in \(Sample sample) -> let mask = encrypt sample
                           in Mask mask

aes256ecbEncrypt :: Key -> (Sample -> Mask)
aes256ecbEncrypt (Key key) =
    let encrypt = ecbEncrypt (throwCryptoError (cipherInit key) :: AES256)
    in \(Sample sample) -> let mask = encrypt sample
                           in Mask mask

chachaEncrypt :: Key -> Sample -> Mask
chachaEncrypt (Key key) (Sample sample0) = Mask mask
  where
    -- fixme: cryptonite hard-codes the counter, sigh
    (_counter,nonce) = BS.splitAt 4 sample0
    st = ChaCha.initialize 20 key nonce
    (mask,_) = ChaCha.combine st "\x0\x0\x0\x0\x0"
