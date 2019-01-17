{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.TLS (
    defaultCipher
  , clientInitialSecret
  , serverInitialSecret
  , aeadKey
  , initialVector
  , headerProtectionKey
  , encryptPayload
  , decryptPayload
  , headerProtection
  , Hash(..)
  , Salt
  , PlainText
  , CipherText
  , Key
  , IV
  , CID
  , Secret
  , AddDat
  , Sample
  , Mask
  , Nonce
  ) where

import Network.TLS.Extra.Cipher
import Crypto.Cipher.AES
import Crypto.Cipher.Types hiding (Cipher, IV)
import Crypto.Error (throwCryptoError)
import Data.Bits
import Data.ByteArray (convert)
import qualified Data.ByteString as B
import Network.ByteOrder
import Network.TLS

import Network.QUIC.Transport.Types

----------------------------------------------------------------

defaultCipher :: Cipher
defaultCipher = cipher_TLS13_AES128GCM_SHA256

----------------------------------------------------------------

type Salt       = ByteString
type PlainText  = ByteString
type CipherText = ByteString
type Key        = ByteString
type IV         = ByteString
type CID        = ByteString -- fixme
type Secret     = ByteString
type AddDat     = ByteString
type Sample     = ByteString
type Mask       = ByteString
type Nonce      = ByteString

----------------------------------------------------------------

-- "ef4fb0abb47470c41befcf8031334fae485e09a0"
initialSalt :: Salt
initialSalt = "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0"

clientInitialSecret :: Cipher -> CID -> Secret
clientInitialSecret = initialSecret "client in"

serverInitialSecret :: Cipher -> CID -> Secret
serverInitialSecret = initialSecret "server in"

initialSecret :: ByteString -> Cipher -> CID -> Secret
initialSecret label cipher cid =
    hkdfExpandLabel hash iniSecret label "" hashSize
  where
    hash = cipherHash cipher
    iniSecret = hkdfExtract hash initialSalt cid
    hashSize = hashDigestSize hash

aeadKey :: Cipher -> Secret -> Key
aeadKey = genKey "quic key"

headerProtectionKey :: Cipher -> Secret -> Key
headerProtectionKey = genKey "quic hp"

genKey :: ByteString -> Cipher -> Secret -> Key
genKey label cipher secret = hkdfExpandLabel hash secret label "" keySize
  where
    hash = cipherHash cipher
    bulk = cipherBulk cipher
    keySize = bulkKeySize bulk

initialVector :: Cipher -> Secret -> IV
initialVector cipher secret = hkdfExpandLabel hash secret "quic iv" "" ivSize
  where
    hash = cipherHash cipher
    bulk = cipherBulk cipher
    ivSize  = max 8 (bulkIVSize bulk + bulkExplicitIV bulk)

----------------------------------------------------------------

cipherEncrypt :: Cipher -> Key -> Nonce -> PlainText -> AddDat -> CipherText
cipherEncrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmEncrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = undefined
  | cipher == cipher_TLS13_AES256GCM_SHA384        = undefined
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = undefined
  | otherwise                                      = error "cipherEncrypt"

cipherDecrypt :: Cipher -> Key -> Nonce -> CipherText -> AddDat -> PlainText
cipherDecrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmDecrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = undefined
  | cipher == cipher_TLS13_AES256GCM_SHA384        = undefined
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = undefined
  | otherwise                                      = error "cipherDecrypt"

aes128gcmEncrypt :: Key -> Nonce -> PlainText -> AddDat -> CipherText
aes128gcmEncrypt key nonce plain ad = encypted `B.append` convert tag
  where
    ctx = throwCryptoError (cipherInit key) :: AES128
    aeadIni = throwCryptoError $ aeadInit AEAD_GCM ctx nonce
    (AuthTag tag, encypted) = aeadSimpleEncrypt aeadIni ad plain 16

aes128gcmDecrypt :: Key -> Nonce -> CipherText -> AddDat -> PlainText
aes128gcmDecrypt key nonce encypted ad = simpleDecrypt aeadIni ad encypted 16
  where
    ctx = throwCryptoError $ cipherInit key :: AES128
    aeadIni = throwCryptoError $ aeadInit AEAD_GCM ctx nonce

simpleDecrypt :: AEAD cipher -> ByteString -> ByteString -> Int -> ByteString
simpleDecrypt aeadIni header encrypted taglen = plain
  where
    aead                = aeadAppendHeader aeadIni header
    (plain, _aeadFinal) = aeadDecrypt aead encrypted
    _tag                = aeadFinalize _aeadFinal taglen

----------------------------------------------------------------

encryptPayload :: Cipher -> Key -> IV -> PacketNumber -> PlainText -> AddDat -> CipherText
encryptPayload cipher key iv pn frames header = encrypt key nonce plain ad
  where
    encrypt = cipherEncrypt cipher
    ivLen = B.length iv
    pnList = loop pn []
    paddedPnList = replicate (ivLen - length pnList) 0 ++ pnList
    nonce = B.pack $ zipWith xor (B.unpack iv) paddedPnList
    plain = frames
    ad = header
    loop 0 ws = ws
    loop n ws = loop (n `shiftR` 8) (fromIntegral n : ws)

decryptPayload :: Cipher -> Key -> IV -> PacketNumber -> CipherText -> AddDat -> PlainText
decryptPayload cipher key iv pn frames header = decrypt key nonce encrypted ad
  where
    decrypt = cipherDecrypt cipher
    ivLen = B.length iv
    pnList = loop pn []
    paddedPnList = replicate (ivLen - length pnList) 0 ++ pnList
    nonce = B.pack $ zipWith xor (B.unpack iv) paddedPnList
    encrypted = frames
    ad = header
    loop 0 ws = ws
    loop n ws = loop (n `shiftR` 8) (fromIntegral n : ws)

----------------------------------------------------------------

headerProtection :: Cipher -> Key -> Sample -> Mask
headerProtection cipher hpKey sample = cipherHeaderProtection cipher hpKey sample

cipherHeaderProtection :: Cipher -> Key -> (Sample -> Mask)
cipherHeaderProtection cipher hpKey
  | cipher == cipher_TLS13_AES128GCM_SHA256        =
    ecbEncrypt (throwCryptoError (cipherInit hpKey) :: AES128)
  | cipher == cipher_TLS13_AES128CCM_SHA256        = undefined
  | cipher == cipher_TLS13_AES256GCM_SHA384        = undefined
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = undefined
  | otherwise                                      = error "cipherHeaderProtection"
