{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Crypto.Keys (
    defaultCipher
  , initialSecrets
  , clientInitialSecret
  , serverInitialSecret
  , aeadKey
  , initialVector
  , nextSecret
  , headerProtectionKey
  ) where

import Network.TLS hiding (Version)
import Network.TLS.Extra.Cipher
import Network.TLS.QUIC
import qualified UnliftIO.Exception as E

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
