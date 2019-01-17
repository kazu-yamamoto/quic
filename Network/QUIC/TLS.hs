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
  ) where

import Network.TLS.Extra.Cipher
import Crypto.Cipher.AES
import Crypto.Cipher.Types hiding (Cipher)
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

clientInitialSecret :: Cipher -> ByteString -> ByteString -> ByteString
clientInitialSecret = initialSecret "client in"

serverInitialSecret :: Cipher -> ByteString -> ByteString -> ByteString
serverInitialSecret = initialSecret "server in"

initialSecret :: ByteString -> Cipher -> ByteString -> ByteString -> ByteString
initialSecret label  cipher salt cid =
    hkdfExpandLabel hash iniSecret label "" hashSize
  where
    hash = cipherHash cipher
    iniSecret = hkdfExtract hash salt cid
    hashSize = hashDigestSize hash

aeadKey :: Cipher -> ByteString -> ByteString
aeadKey = genKey "quic key"

headerProtectionKey :: Cipher -> ByteString -> ByteString
headerProtectionKey = genKey "quic hp"

genKey :: ByteString -> Cipher -> ByteString -> ByteString
genKey label cipher secret = hkdfExpandLabel hash secret label "" size
  where
    hash = cipherHash cipher
    size = bulkKeySize $ cipherBulk cipher

initialVector :: Cipher -> ByteString -> ByteString
initialVector cipher secret = hkdfExpandLabel hash secret "quic iv" "" 12 -- fixme
  where
    hash = cipherHash cipher

----------------------------------------------------------------

cipherEncrypt :: Cipher -> ByteString -> ByteString -> ByteString -> ByteString -> ByteString
cipherEncrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmEncrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = undefined
  | cipher == cipher_TLS13_AES256GCM_SHA384        = undefined
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = undefined
  | otherwise                                      = error "cipherEncrypt"

cipherDecrypt :: Cipher -> ByteString -> ByteString -> ByteString -> ByteString -> ByteString
cipherDecrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmDecrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = undefined
  | cipher == cipher_TLS13_AES256GCM_SHA384        = undefined
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = undefined
  | otherwise                                      = error "cipherDecrypt"

aes128gcmEncrypt :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString
aes128gcmEncrypt key nonce plain ad = encypted `B.append` convert tag
  where
    ctx = throwCryptoError (cipherInit key) :: AES128
    aeadIni = throwCryptoError $ aeadInit AEAD_GCM ctx nonce
    (AuthTag tag, encypted) = aeadSimpleEncrypt aeadIni ad plain 16

aes128gcmDecrypt :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString
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

encryptPayload :: Cipher -> ByteString -> ByteString -> PacketNumber -> ByteString -> ByteString -> ByteString
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

decryptPayload :: Cipher -> ByteString -> ByteString -> PacketNumber -> ByteString -> ByteString -> ByteString
decryptPayload cipher key _iv _pn frames _header = decrypt key nonce encrypted ad
  where
    decrypt = cipherDecrypt cipher
    encrypted = frames
    ad = undefined
    nonce = undefined

----------------------------------------------------------------

headerProtection :: ByteString -> ByteString -> ByteString
headerProtection hpKey sampl = ecbEncrypt cipher sampl
  where
    cipher = throwCryptoError (cipherInit hpKey) :: AES128
