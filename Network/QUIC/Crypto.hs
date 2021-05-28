{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Crypto (
  -- * Payload encryption
    defaultCipher
  , initialSecrets
  , clientInitialSecret
  , serverInitialSecret
  , aeadKey
  , initialVector
  , nextSecret
  , headerProtectionKey
  , makeNonce
  , encryptPayload
  , encryptPayload'
  , decryptPayload
  , decryptPayload'
  -- * Header Protection
  , protectionMask
  , tagLength
  , sampleLength
  , bsXOR
--  , unprotectHeader
  -- * Types
  , PlainText
  , CipherText
  , Key(..)
  , IV(..)
  , CID
  , Secret(..)
  , AddDat(..)
  , Sample(..)
  , Mask(..)
  , Nonce(..)
  , Cipher
  , InitialSecret
  , TrafficSecrets
  , ClientTrafficSecret(..)
  , ServerTrafficSecret(..)
  -- * Misc
  , calculateIntegrityTag
  ) where

import Crypto.Cipher.AES
import qualified Crypto.Cipher.ChaCha as ChaCha
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly
import Crypto.Cipher.Types hiding (Cipher, IV)
import Crypto.Error (throwCryptoError, maybeCryptoError)
import qualified Crypto.MAC.Poly1305 as Poly1305
import qualified Data.ByteArray as Byte (convert, xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Internal as BS
import qualified Data.ByteString.Short as Short
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (peek, poke)
import Network.TLS hiding (Version)
import Network.TLS.Extra.Cipher
import Network.TLS.QUIC
import qualified UnliftIO.Exception as E

import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

defaultCipher :: Cipher
defaultCipher = cipher_TLS13_AES128GCM_SHA256

----------------------------------------------------------------

type PlainText  = ByteString
type CipherText = ByteString
type Salt       = ByteString

newtype Key    = Key    ByteString deriving (Eq)
newtype IV     = IV     ByteString deriving (Eq)
newtype Secret = Secret ByteString deriving (Eq)
newtype AddDat = AddDat ByteString deriving (Eq)
newtype Sample = Sample ByteString deriving (Eq)
newtype Mask   = Mask   ByteString deriving (Eq)
newtype Label  = Label  ByteString deriving (Eq)
newtype Nonce  = Nonce  ByteString deriving (Eq)

instance Show Key where
    show (Key x) = "Key=" ++ C8.unpack (enc16 x)
instance Show IV where
    show (IV x) = "IV=" ++ C8.unpack (enc16 x)
instance Show Secret where
    show (Secret x) = "Secret=" ++ C8.unpack (enc16 x)
instance Show AddDat where
    show (AddDat x) = "AddDat=" ++ C8.unpack (enc16 x)
instance Show Sample where
    show (Sample x) = "Sample=" ++ C8.unpack (enc16 x)
instance Show Mask where
    show (Mask x) = "Mask=" ++ C8.unpack (enc16 x)
instance Show Label where
    show (Label x) = "Label=" ++ C8.unpack (enc16 x)
instance Show Nonce where
    show (Nonce x) = "Nonce=" ++ C8.unpack (enc16 x)

----------------------------------------------------------------

initialSalt :: Version -> Salt
initialSalt Draft29     = "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99"
initialSalt Version1    = "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"
initialSalt (Version v) = E.impureThrow $ VersionIsUnknown v

data InitialSecret

initialSecrets :: Version -> CID -> TrafficSecrets InitialSecret
initialSecrets v c = (clientInitialSecret v c, serverInitialSecret v c)

clientInitialSecret :: Version -> CID -> ClientTrafficSecret InitialSecret
clientInitialSecret v c = ClientTrafficSecret $ initialSecret (Label "client in") v c

serverInitialSecret :: Version -> CID -> ServerTrafficSecret InitialSecret
serverInitialSecret v c = ServerTrafficSecret $ initialSecret (Label "server in") v c

initialSecret :: Label -> Version -> CID -> ByteString
initialSecret (Label label) ver cid = secret
  where
    cipher    = defaultCipher
    hash      = cipherHash cipher
    iniSecret = hkdfExtract hash (initialSalt ver) $ fromCID cid
    hashSize  = hashDigestSize hash
    secret    = hkdfExpandLabel hash iniSecret label "" hashSize

aeadKey :: Cipher -> Secret -> Key
aeadKey = genKey (Label "quic key")

headerProtectionKey :: Cipher -> Secret -> Key
headerProtectionKey = genKey (Label "quic hp")

genKey :: Label -> Cipher -> Secret -> Key
genKey (Label label) cipher (Secret secret) = Key key
  where
    hash    = cipherHash cipher
    bulk    = cipherBulk cipher
    keySize = bulkKeySize bulk
    key     = hkdfExpandLabel hash secret label "" keySize

initialVector :: Cipher -> Secret -> IV
initialVector cipher (Secret secret) = IV iv
  where
    hash   = cipherHash cipher
    bulk   = cipherBulk cipher
    ivSize = max 8 (bulkIVSize bulk + bulkExplicitIV bulk)
    iv     = hkdfExpandLabel hash secret "quic iv" "" ivSize

nextSecret :: Cipher -> Secret -> Secret
nextSecret cipher (Secret secN) = Secret secN1
  where
    label    = "quic ku"
    hash     = cipherHash cipher
    hashSize = hashDigestSize hash
    secN1    = hkdfExpandLabel hash secN label "" hashSize

----------------------------------------------------------------

-- It would be nice to take [PlainText] and update AEAD context with
-- [PlainText]. But since each PlainText is not aligned to cipher block,
-- it's impossible.
cipherEncrypt :: Cipher -> Key -> Nonce -> PlainText -> AddDat -> [CipherText]
cipherEncrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmEncrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = error "cipher_TLS13_AES128CCM_SHA256"
  | cipher == cipher_TLS13_AES256GCM_SHA384        = aes256gcmEncrypt
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = chacha20poly1305Encrypt
  | otherwise                                      = error "cipherEncrypt"

cipherDecrypt :: Cipher -> Key -> Nonce -> CipherText -> AddDat -> Maybe PlainText
cipherDecrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmDecrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = error "cipher_TLS13_AES128CCM_SHA256"
  | cipher == cipher_TLS13_AES256GCM_SHA384        = aes256gcmDecrypt
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = chacha20poly1305Decrypt
  | otherwise                                      = error "cipherDecrypt"

-- IMPORTANT: Using 'let' so that parameters can be memorized.
aes128gcmEncrypt :: Key -> (Nonce -> PlainText -> AddDat -> [CipherText])
aes128gcmEncrypt (Key key) =
    let aes = throwCryptoError (cipherInit key) :: AES128
    in \(Nonce nonce) plaintext (AddDat ad) ->
      let aead = throwCryptoError $ aeadInit AEAD_GCM aes nonce
          (AuthTag tag0, ciphertext) = aeadSimpleEncrypt aead ad plaintext 16
          tag = Byte.convert tag0
      in [ciphertext,tag]

aes128gcmDecrypt :: Key -> (Nonce -> CipherText -> AddDat -> Maybe PlainText)
aes128gcmDecrypt (Key key) =
    let aes = throwCryptoError (cipherInit key) :: AES128
    in \(Nonce nonce) ciphertag (AddDat ad) ->
      let aead = throwCryptoError $ aeadInit AEAD_GCM aes nonce
          (ciphertext, tag) = BS.splitAt (BS.length ciphertag - 16) ciphertag
          authtag = AuthTag $ Byte.convert tag
       in aeadSimpleDecrypt aead ad ciphertext authtag

aes256gcmEncrypt :: Key -> (Nonce -> PlainText -> AddDat -> [CipherText])
aes256gcmEncrypt (Key key) =
    let aes = throwCryptoError (cipherInit key) :: AES256
    in \(Nonce nonce) plaintext (AddDat ad) ->
      let aead = throwCryptoError $ aeadInit AEAD_GCM aes nonce
          (AuthTag tag0, ciphertext) = aeadSimpleEncrypt aead ad plaintext 16
          tag = Byte.convert tag0
      in [ciphertext, tag]

aes256gcmDecrypt :: Key -> (Nonce -> CipherText -> AddDat -> Maybe PlainText)
aes256gcmDecrypt (Key key) =
    let aes = throwCryptoError (cipherInit key) :: AES256
    in \(Nonce nonce) ciphertag (AddDat ad) ->
      let aead = throwCryptoError $ aeadInit AEAD_GCM aes nonce
          (ciphertext, tag) = BS.splitAt (BS.length ciphertag - 16) ciphertag
          authtag = AuthTag $ Byte.convert tag
      in aeadSimpleDecrypt aead ad ciphertext authtag

chacha20poly1305Encrypt :: Key -> Nonce -> PlainText -> AddDat -> [CipherText]
chacha20poly1305Encrypt (Key key) (Nonce nonce) plaintext (AddDat ad) =
    [ciphertext,Byte.convert tag]
  where
    st1 = throwCryptoError (ChaChaPoly.nonce12 nonce >>= ChaChaPoly.initialize key)
    st2 = ChaChaPoly.finalizeAAD (ChaChaPoly.appendAAD ad st1)
    (ciphertext, st3) = ChaChaPoly.encrypt plaintext st2
    Poly1305.Auth tag = ChaChaPoly.finalize st3

chacha20poly1305Decrypt :: Key -> Nonce -> CipherText -> AddDat -> Maybe PlainText
chacha20poly1305Decrypt (Key key) (Nonce nonce) ciphertag (AddDat ad) = do
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

----------------------------------------------------------------

encryptPayload :: Cipher -> Key -> IV
               -> (PlainText -> ByteString -> PacketNumber -> [CipherText])
encryptPayload cipher key iv =
    let enc = cipherEncrypt cipher key
        mk  = makeNonce iv
    in \plaintext header pn -> let bytePN = bytestring64 $ fromIntegral pn
                                   nonce  = mk bytePN
                               in enc nonce plaintext (AddDat header)

encryptPayload' :: Cipher -> Key -> Nonce -> PlainText -> AddDat -> [CipherText]
encryptPayload' cipher key nonce plaintext header =
    cipherEncrypt cipher key nonce plaintext header

----------------------------------------------------------------

decryptPayload :: Cipher -> Key -> IV
               -> (CipherText -> ByteString -> PacketNumber -> Maybe PlainText)
decryptPayload cipher key iv =
    let dec = cipherDecrypt cipher key
        mk  = makeNonce iv
    in \ciphertext header pn -> let bytePN = bytestring64 (fromIntegral pn)
                                    nonce = mk bytePN
                                in dec nonce ciphertext (AddDat header)

decryptPayload' :: Cipher -> Key -> Nonce -> CipherText -> AddDat -> Maybe PlainText
decryptPayload' cipher key nonce ciphertext header =
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

tagLength :: Cipher -> Int
tagLength cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = 16
  | cipher == cipher_TLS13_AES128CCM_SHA256        = 16
  | cipher == cipher_TLS13_AES256GCM_SHA384        = 16
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = 16 -- fixme
  | otherwise                                      = error "tagLength"

sampleLength :: Cipher -> Int
sampleLength cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = 16
  | cipher == cipher_TLS13_AES128CCM_SHA256        = 16
  | cipher == cipher_TLS13_AES256GCM_SHA384        = 16
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = 16 -- fixme
  | otherwise                                      = error "sampleLength"

bsXOR :: ByteString -> ByteString -> ByteString
bsXOR = Byte.xor

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

calculateIntegrityTag :: Version -> CID -> ByteString -> ByteString
calculateIntegrityTag ver oCID pseudo0 =
    BS.concat $ aes128gcmEncrypt key nonce "" (AddDat pseudo)
  where
    (ocid, ocidlen) = unpackCID oCID
    pseudo = BS.concat [BS.singleton ocidlen
                       ,Short.fromShort ocid
                       ,pseudo0]
    key | ver == Version1 = Key "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e"
        | otherwise       = Key "\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1"
    nonce | ver == Version1 = Nonce "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb"
          | otherwise       = Nonce "\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c"
