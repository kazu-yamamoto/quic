{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.TLS (
  -- * TLS
    clientController
  , serverController
  -- * Payload encryption
  , defaultCipher
  , initialSecrets
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
  , InitialSecret
  , TrafficSecrets
  , ClientTrafficSecret(..)
  , ServerTrafficSecret(..)
  ) where

import Crypto.Cipher.AES
import Crypto.Cipher.Types hiding (Cipher, IV)
import Crypto.Error (throwCryptoError)
import Data.ByteArray (convert)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Data.Default.Class
import Network.TLS hiding (Version)
import Network.TLS.Extra.Cipher
import Network.TLS.QUIC

import Network.QUIC.Imports
import Network.QUIC.Transport.Types

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
-- "ef4fb0abb47470c41befcf8031334fae485e09a0"
initialSalt Draft18 = "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0"
initialSalt Draft19 = "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0"
initialSalt Draft20 = "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0"
-- "7fbcdb0e7c66bbe9193a96cd21519ebd7a02644a"
initialSalt Draft21 = "\x7f\xbc\xdb\x0e\x7c\x66\xbb\xe9\x19\x3a\x96\xcd\x21\x51\x9e\xbd\x7a\x02\x64\x4a"
initialSalt Draft22 = "\x7f\xbc\xdb\x0e\x7c\x66\xbb\xe9\x19\x3a\x96\xcd\x21\x51\x9e\xbd\x7a\x02\x64\x4a"
-- "c3eef712c72ebb5a11a7d2432bb46365bef9f502"
initialSalt Draft23 = "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02"
initialSalt Draft24 = "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02"
initialSalt _       = error "initialSalt"

data InitialSecret

initialSecrets :: Version -> CID -> TrafficSecrets InitialSecret
initialSecrets v c = (clientInitialSecret v c, serverInitialSecret v c)

clientInitialSecret :: Version -> CID -> ClientTrafficSecret InitialSecret
clientInitialSecret v c = ClientTrafficSecret $ initialSecret (Label "client in") v c

serverInitialSecret :: Version -> CID -> ServerTrafficSecret InitialSecret
serverInitialSecret v c = ServerTrafficSecret $ initialSecret (Label "server in") v c

initialSecret :: Label -> Version -> CID -> ByteString
initialSecret (Label label) ver (CID cid) = secret
  where
    cipher    = defaultCipher
    hash      = cipherHash cipher
    iniSecret = hkdfExtract hash (initialSalt ver) cid
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

----------------------------------------------------------------

cipherEncrypt :: Cipher -> Key -> Nonce -> PlainText -> AddDat -> CipherText
cipherEncrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmEncrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = error "cipher_TLS13_AES128CCM_SHA256"
  | cipher == cipher_TLS13_AES256GCM_SHA384        = aes256gcmEncrypt
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = error "cipher_TLS13_CHACHA20POLY1305_SHA256"
  | otherwise                                      = error "cipherEncrypt"

cipherDecrypt :: Cipher -> Key -> Nonce -> CipherText -> AddDat -> Maybe PlainText
cipherDecrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmDecrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = error "cipher_TLS13_AES128CCM_SHA256"
  | cipher == cipher_TLS13_AES256GCM_SHA384        = aes256gcmDecrypt
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = error "cipher_TLS13_CHACHA20POLY1305_SHA256"
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

aes256gcmEncrypt :: Key -> Nonce -> PlainText -> AddDat -> CipherText
aes256gcmEncrypt (Key key) (Nonce nonce) plaintext (AddDat ad) =
    ciphertext `B.append` convert tag
  where
    ctx = throwCryptoError (cipherInit key) :: AES256
    aeadIni = throwCryptoError $ aeadInit AEAD_GCM ctx nonce
    (AuthTag tag, ciphertext) = aeadSimpleEncrypt aeadIni ad plaintext 16

aes256gcmDecrypt :: Key -> Nonce -> CipherText -> AddDat -> Maybe PlainText
aes256gcmDecrypt (Key key) (Nonce nonce) ciphertag (AddDat ad) = plaintext
  where
    ctx = throwCryptoError $ cipherInit key :: AES256
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
  | cipher == cipher_TLS13_AES128CCM_SHA256        = error "cipher_TLS13_AES128CCM_SHA256"
  | cipher == cipher_TLS13_AES256GCM_SHA384        = aes256ecbEncrypt key
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = error "cipher_TLS13_CHACHA20POLY1305_SHA256"
  | otherwise                                      = error "cipherHeaderProtection"

aes128ecbEncrypt :: Key -> Sample -> Mask
aes128ecbEncrypt (Key key) (Sample sample) = Mask mask
  where
    encrypt = ecbEncrypt (throwCryptoError (cipherInit key) :: AES128)
    mask = encrypt sample

aes256ecbEncrypt :: Key -> Sample -> Mask
aes256ecbEncrypt (Key key) (Sample sample) = Mask mask
  where
    encrypt = ecbEncrypt (throwCryptoError (cipherInit key) :: AES256)
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

----------------------------------------------------------------

clientController:: String -> [Cipher]
                -> IO (Maybe [ByteString]) -> ByteString
                -> IO ClientController
clientController serverName ciphers suggestALPN quicParams =
    newQUICClient cparams
  where
    cparams = (defaultParamsClient serverName "") {
        clientDebug     = debug
      , clientHooks     = hook
      , clientShared    = cshared
      , clientSupported = supported
      }
    debug = def
--    debug = def {
--        debugKeyLogger = putStrLn
--      }
    hook = def {
        onSuggestALPN = suggestALPN
      }
    cshared = def {
        sharedValidationCache = ValidationCache (\_ _ _ -> return ValidationCachePass) (\_ _ _ -> return ())
      , sharedExtensions = [ExtensionRaw extensionID_QuicTransportParameters quicParams]
      }
    supported = def {
        supportedVersions = [TLS13]
      , supportedCiphers  = ciphers
      }

serverController :: FilePath -> FilePath
                 -> Maybe ([ByteString] -> IO ByteString)
                 -> ByteString
                 -> IO ServerController
serverController key cert selectALPN quicParams = do
    Right cred <- credentialLoadX509 cert key
    let sshared = def {
            sharedCredentials = Credentials [cred]
          , sharedExtensions = [ExtensionRaw extensionID_QuicTransportParameters quicParams]
          }
    let sparams = def {
        serverDebug     = debug
      , serverHooks     = hook
      , serverShared    = sshared
      , serverSupported = supported
      }
    newQUICServer sparams
  where
    supported = def {
        supportedVersions = [TLS13]
      , supportedCiphers = ciphersuite_strong
      }
    debug = def
--    debug = def {
--        debugKeyLogger = putStrLn
--      }
    hook = def {
        onALPNClientSuggest = selectALPN
      }
