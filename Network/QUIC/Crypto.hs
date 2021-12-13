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

import qualified Data.ByteArray as Byte (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as Short
import Network.TLS hiding (Version)
import Network.TLS.Extra.Cipher
import Network.TLS.QUIC
import qualified UnliftIO.Exception as E

import Network.QUIC.Crypto.Nite
import Network.QUIC.Crypto.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

defaultCipher :: Cipher
defaultCipher = cipher_TLS13_AES128GCM_SHA256

----------------------------------------------------------------

initialSalt :: Version -> Salt
initialSalt Draft29     = "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99"
initialSalt Version1    = "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"
initialSalt Version2    = "\xa7\x07\xc2\x03\xa5\x9b\x47\x18\x4a\x1d\x62\xca\x57\x04\x06\xea\x7a\xe3\xe5\xd3"
initialSalt (Version v) = E.impureThrow $ VersionIsUnknown v

initialSecrets :: Version -> CID -> TrafficSecrets InitialSecret
initialSecrets v c = (clientInitialSecret v c, serverInitialSecret v c)

clientInitialSecret :: Version -> CID -> ClientTrafficSecret InitialSecret
clientInitialSecret v c = ClientTrafficSecret $ initialSecret v c $ Label "client in"

serverInitialSecret :: Version -> CID -> ServerTrafficSecret InitialSecret
serverInitialSecret v c = ServerTrafficSecret $ initialSecret v c $ Label "server in"

initialSecret :: Version -> CID -> Label -> ByteString
initialSecret Draft29  = initialSecret' $ initialSalt Draft29
initialSecret Version1 = initialSecret' $ initialSalt Version1
initialSecret Version2 = initialSecret' $ initialSalt Version2
initialSecret _        = \_ _ -> "not supported"

initialSecret' :: ByteString -> CID -> Label -> ByteString
initialSecret' salt cid (Label label) = secret
  where
    cipher    = defaultCipher
    hash      = cipherHash cipher
    iniSecret = hkdfExtract hash salt $ fromCID cid
    hashSize  = hashDigestSize hash
    secret    = hkdfExpandLabel hash iniSecret label "" hashSize

aeadKey :: Version -> Cipher -> Secret -> Key
aeadKey Draft29  = genKey $ Label "quic key"
aeadKey Version1 = genKey $ Label "quic key"
aeadKey Version2 = genKey $ Label "quicv2 key"
aeadKey _        = genKey $ Label "not supported"

headerProtectionKey :: Version -> Cipher -> Secret -> Key
headerProtectionKey Draft29  = genKey $ Label "quic hp"
headerProtectionKey Version1 = genKey $ Label "quic hp"
headerProtectionKey Version2 = genKey $ Label "quicv2 hp"
headerProtectionKey _        = genKey $ Label "not supported"

genKey :: Label -> Cipher -> Secret -> Key
genKey (Label label) cipher (Secret secret) = Key key
  where
    hash    = cipherHash cipher
    bulk    = cipherBulk cipher
    keySize = bulkKeySize bulk
    key     = hkdfExpandLabel hash secret label "" keySize

initialVector :: Version -> Cipher -> Secret -> IV
initialVector ver cipher (Secret secret) = IV iv
  where
    label  = ivLabel ver
    hash   = cipherHash cipher
    bulk   = cipherBulk cipher
    ivSize = max 8 (bulkIVSize bulk + bulkExplicitIV bulk)
    iv     = hkdfExpandLabel hash secret label "" ivSize

ivLabel :: Version -> ByteString
ivLabel Draft29  = "quic iv"
ivLabel Version1 = "quic iv"
ivLabel Version2 = "quicv2 iv"
ivLabel _        = "not supported"

nextSecret :: Version -> Cipher -> Secret -> Secret
nextSecret ver cipher (Secret secN) = Secret secN1
  where
    label    = kuLabel ver
    hash     = cipherHash cipher
    hashSize = hashDigestSize hash
    secN1    = hkdfExpandLabel hash secN label "" hashSize

kuLabel :: Version -> ByteString
kuLabel Draft29  = "quic ku"
kuLabel Version1 = "quic ku"
kuLabel Version2 = "quicv2 ku"
kuLabel _        = "not supported"

bsXOR :: ByteString -> ByteString -> ByteString
bsXOR = Byte.xor

----------------------------------------------------------------

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

----------------------------------------------------------------

calculateIntegrityTag :: Version -> CID -> ByteString -> ByteString
calculateIntegrityTag ver oCID pseudo0 =
    BS.concat $ aes128gcmEncrypt (key ver) (nonce ver) "" (AddDat pseudo)
  where
    (ocid, ocidlen) = unpackCID oCID
    pseudo = BS.concat [BS.singleton ocidlen
                       ,Short.fromShort ocid
                       ,pseudo0]
    key Draft29  = Key "\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1"
    key Version1 = Key "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e"
    key Version2 = Key "\xba\x85\x8d\xc7\xb4\x3d\xe5\xdb\xf8\x76\x17\xff\x4a\xb2\x53\xdb"
    key _        = Key "not supported"
    nonce Draft29  = Nonce "\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c"
    nonce Version1 = Nonce "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb"
    nonce Version2 = Nonce "\x14\x1b\x99\xc2\x39\xb0\x3e\x78\x5d\x6a\x2e\x9f"
    nonce _        = Nonce "not supported"
