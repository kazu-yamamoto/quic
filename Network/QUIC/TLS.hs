{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC.TLS (
  -- * Payload encryption
    defaultCipher
  , clientInitialSecret
  , serverInitialSecret
  , aeadKey
  , initialVector
  , headerProtectionKey
  , makeNonce
  , encryptPayload
  , decryptPayload
  -- * Header Protection
  , protectionMask
  , sampleLength
  , bsXOR
--  , unprotectHeader
  -- * Types
  , PlainText
  , CipherText
  , Key(..)
  , IV(..)
  , CID(..)
  , Secret(..)
  , AddDat(..)
  , Sample(..)
  , Mask(..)
  , Nonce(..)
  , Cipher
  ) where

import Network.TLS.Extra.Cipher
import Crypto.Cipher.AES
import Crypto.Cipher.Types hiding (Cipher, IV)
import Crypto.Error (throwCryptoError)
import Data.Bits
import Data.ByteArray (convert)
import qualified Data.ByteString as B
import Network.ByteOrder
import Network.TLS (Cipher)
import qualified Network.TLS as TLS

----------------------------------------------------------------

defaultCipher :: Cipher
defaultCipher = cipher_TLS13_AES128GCM_SHA256

----------------------------------------------------------------

type PlainText  = ByteString
type CipherText = ByteString
type Salt       = ByteString

newtype Key    = Key    ByteString deriving (Eq, Show)
newtype IV     = IV     ByteString deriving (Eq, Show)
newtype CID    = CID    ByteString deriving (Eq, Show)
newtype Secret = Secret ByteString deriving (Eq, Show)
newtype AddDat = AddDat ByteString deriving (Eq, Show)
newtype Sample = Sample ByteString deriving (Eq, Show)
newtype Mask   = Mask   ByteString deriving (Eq, Show)
newtype Label  = Label  ByteString deriving (Eq, Show)
newtype Nonce  = Nonce  ByteString deriving (Eq, Show)

----------------------------------------------------------------

-- "ef4fb0abb47470c41befcf8031334fae485e09a0"
initialSalt :: Salt
initialSalt = "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0"

clientInitialSecret :: Cipher -> CID -> Secret
clientInitialSecret = initialSecret (Label "client in")

serverInitialSecret :: Cipher -> CID -> Secret
serverInitialSecret = initialSecret (Label "server in")

initialSecret :: Label -> Cipher -> CID -> Secret
initialSecret (Label label) cipher (CID cid) = Secret secret
  where
    hash      = TLS.cipherHash cipher
    iniSecret = TLS.hkdfExtract hash initialSalt cid
    hashSize  = TLS.hashDigestSize hash
    secret    = TLS.hkdfExpandLabel hash iniSecret label "" hashSize

aeadKey :: Cipher -> Secret -> Key
aeadKey = genKey (Label "quic key")

headerProtectionKey :: Cipher -> Secret -> Key
headerProtectionKey = genKey (Label "quic hp")

genKey :: Label -> Cipher -> Secret -> Key
genKey (Label label) cipher (Secret secret) = Key key
  where
    hash    = TLS.cipherHash cipher
    bulk    = TLS.cipherBulk cipher
    keySize = TLS.bulkKeySize bulk
    key     = TLS.hkdfExpandLabel hash secret label "" keySize

initialVector :: Cipher -> Secret -> IV
initialVector cipher (Secret secret) = IV iv
  where
    hash   = TLS.cipherHash cipher
    bulk   = TLS.cipherBulk cipher
    ivSize = max 8 (TLS.bulkIVSize bulk + TLS.bulkExplicitIV bulk)
    iv     = TLS.hkdfExpandLabel hash secret "quic iv" "" ivSize

----------------------------------------------------------------

cipherEncrypt :: Cipher -> Key -> Nonce -> PlainText -> AddDat -> CipherText
cipherEncrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmEncrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = undefined
  | cipher == cipher_TLS13_AES256GCM_SHA384        = undefined
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = undefined
  | otherwise                                      = error "cipherEncrypt"

cipherDecrypt :: Cipher -> Key -> Nonce -> CipherText -> AddDat -> Maybe PlainText
cipherDecrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmDecrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = undefined
  | cipher == cipher_TLS13_AES256GCM_SHA384        = undefined
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = undefined
  | otherwise                                      = error "cipherDecrypt"

aes128gcmEncrypt :: Key -> Nonce -> PlainText -> AddDat -> CipherText
aes128gcmEncrypt (Key key) (Nonce nonce) plaintext (AddDat ad) =
    ciphertext `B.append` convert tag
  where
    ctx = throwCryptoError (cipherInit key) :: AES128
    aeadIni = throwCryptoError $ aeadInit AEAD_GCM ctx nonce
    (AuthTag tag, ciphertext) = aeadSimpleEncrypt aeadIni ad plaintext 16

aes128gcmDecrypt :: Key -> Nonce -> CipherText -> AddDat -> Maybe PlainText
aes128gcmDecrypt (Key key) (Nonce nonce) ciphertag (AddDat ad) = plaintext
  where
    ctx = throwCryptoError $ cipherInit key :: AES128
    aeadIni = throwCryptoError $ aeadInit AEAD_GCM ctx nonce
    (ciphertext, tag) = B.splitAt (B.length ciphertag - 16) ciphertag
    authtag = AuthTag $ convert tag
    plaintext = aeadSimpleDecrypt aeadIni ad ciphertext authtag

----------------------------------------------------------------

makeNonce :: IV -> ByteString -> Nonce
makeNonce (IV iv) pn = Nonce nonce
  where
    nonce = bsXORpad iv pn

encryptPayload :: Cipher -> Key -> Nonce -> PlainText -> AddDat -> CipherText
encryptPayload cipher key nonce plaintext header =
    cipherEncrypt cipher key nonce plaintext header

decryptPayload :: Cipher -> Key -> Nonce -> CipherText -> AddDat -> Maybe PlainText
decryptPayload cipher key nonce ciphertext header =
    cipherDecrypt cipher key nonce ciphertext header

----------------------------------------------------------------

protectionMask :: Cipher -> Key -> Sample -> Mask
protectionMask cipher key sample = cipherHeaderProtection cipher key sample

cipherHeaderProtection :: Cipher -> Key -> (Sample -> Mask)
cipherHeaderProtection cipher key
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128ecbEncrypt key
  | cipher == cipher_TLS13_AES128CCM_SHA256        = undefined
  | cipher == cipher_TLS13_AES256GCM_SHA384        = undefined
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = undefined
  | otherwise                                      = error "cipherHeaderProtection"

aes128ecbEncrypt :: Key -> Sample -> Mask
aes128ecbEncrypt (Key key) (Sample sample) = Mask mask
  where
    encrypt = ecbEncrypt (throwCryptoError (cipherInit key) :: AES128)
    mask = encrypt sample

sampleLength :: Cipher -> Int
sampleLength cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = 16
  | cipher == cipher_TLS13_AES128CCM_SHA256        = 16
  | cipher == cipher_TLS13_AES256GCM_SHA384        = 16
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = 16
  | otherwise                                      = error "sampleLength"

bsXOR :: ByteString -> ByteString -> ByteString
bsXOR bs1 bs2 = B.pack $ map (uncurry xor) $ B.zip bs1 bs2

bsXORpad :: ByteString -> ByteString -> ByteString
bsXORpad iv pn = B.pack $ map (uncurry xor) $ zip ivl pnl
  where
    ivl = B.unpack iv
    diff = B.length iv - B.length pn
    pnl = replicate diff 0 ++ B.unpack pn
