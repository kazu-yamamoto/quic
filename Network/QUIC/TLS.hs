{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC.TLS (
  -- * TLS
    tlsClientContext
  , tlsServerContext
  -- * Payload encryption
  , defaultCipher
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
  , HandshakeCheck(..)
  , handshakeCheck
  ) where

import Crypto.Cipher.AES
import Crypto.Cipher.Types hiding (Cipher, IV)
import Crypto.Error (throwCryptoError)
import Data.Bits
import Data.ByteArray (convert)
import qualified Data.ByteString as B
import Data.Default.Class
import Network.ByteOrder
import Network.TLS (Cipher)
import qualified Network.TLS as TLS
import qualified Network.TLS.Extra.Cipher as TLS
import Network.TLS.Extra.Cipher

import Network.QUIC.Transport.Types

----------------------------------------------------------------

defaultCipher :: Cipher
defaultCipher = cipher_TLS13_AES128GCM_SHA256

----------------------------------------------------------------

type PlainText  = ByteString
type CipherText = ByteString
type Salt       = ByteString

newtype Key    = Key    ByteString deriving (Eq, Show)
newtype IV     = IV     ByteString deriving (Eq, Show)
newtype Secret = Secret ByteString deriving (Eq, Show)
newtype AddDat = AddDat ByteString deriving (Eq, Show)
newtype Sample = Sample ByteString deriving (Eq, Show)
newtype Mask   = Mask   ByteString deriving (Eq, Show)
newtype Label  = Label  ByteString deriving (Eq, Show)
newtype Nonce  = Nonce  ByteString deriving (Eq, Show)

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
initialSalt _       = error "initialSalt"

clientInitialSecret :: Version -> CID -> Secret
clientInitialSecret = initialSecret (Label "client in")

serverInitialSecret :: Version -> CID -> Secret
serverInitialSecret = initialSecret (Label "server in")

initialSecret :: Label -> Version -> CID -> Secret
initialSecret (Label label) ver (CID cid) = Secret secret
  where
    cipher    = defaultCipher
    hash      = TLS.cipherHash cipher
    iniSecret = TLS.hkdfExtract hash (initialSalt ver) cid
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
  | cipher == cipher_TLS13_AES128CCM_SHA256        = error "cipher_TLS13_AES128CCM_SHA256"
  | cipher == cipher_TLS13_AES256GCM_SHA384        = error "cipher_TLS13_AES256GCM_SHA384"
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = error "cipher_TLS13_CHACHA20POLY1305_SHA256"
  | otherwise                                      = error "cipherEncrypt"

cipherDecrypt :: Cipher -> Key -> Nonce -> CipherText -> AddDat -> Maybe PlainText
cipherDecrypt cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = aes128gcmDecrypt
  | cipher == cipher_TLS13_AES128CCM_SHA256        = error "cipher_TLS13_AES128CCM_SHA256"
  | cipher == cipher_TLS13_AES256GCM_SHA384        = error "cipher_TLS13_AES256GCM_SHA384"
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
  | cipher == cipher_TLS13_AES256GCM_SHA384        = error "cipher_TLS13_AES256GCM_SHA384"
  | cipher == cipher_TLS13_CHACHA20POLY1305_SHA256 = error "cipher_TLS13_CHACHA20POLY1305_SHA256"
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

----------------------------------------------------------------

tlsClientContext :: TLS.HostName -> [Cipher] -> IO (Maybe [ByteString]) -> IO (TLS.Context, TLS.ClientParams)
tlsClientContext serverName ciphers suggestALPN  = do
    ctx <- TLS.contextNew backend cparams
    return (ctx, cparams)
  where
    backend = TLS.Backend (return ())
                          (return ())
                          (\_ -> return ()) (\_ -> return "")
    cparams = (TLS.defaultParamsClient serverName "") {
        TLS.clientDebug     = debug
      , TLS.clientHooks     = hook
      , TLS.clientShared    = cshared
      , TLS.clientSupported = supported
      }
    debug = def {
        TLS.debugKeyLogger = putStrLn -- fixme
      }
    hook = def {
        TLS.onSuggestALPN = suggestALPN
      }
    cshared = def {
       TLS.sharedValidationCache = TLS.ValidationCache (\_ _ _ -> return TLS.ValidationCachePass) (\_ _ _ -> return ())
      }
    supported = def {
        TLS.supportedVersions = [TLS.TLS13]
      , TLS.supportedCiphers  = ciphers
      }

tlsServerContext :: FilePath -> FilePath -> IO (TLS.Context, TLS.ServerParams)
tlsServerContext key cert = do
    Right cred <- TLS.credentialLoadX509 cert key
    let sshared = def {
            TLS.sharedCredentials = TLS.Credentials [cred]
          }
    let sparams = def {
        TLS.serverSupported = supported
      , TLS.serverDebug = debug
      , TLS.serverShared = sshared
      }
    ctx <- TLS.contextNew backend sparams
    return (ctx, sparams)
  where
    backend = TLS.Backend (return ())
                          (return ())
                          (\_ -> return ()) (\_ -> return "")
    supported = def {
        TLS.supportedVersions = [TLS.TLS13]
      , TLS.supportedCiphers = TLS.ciphersuite_strong
      }
    debug = def {
        TLS.debugKeyLogger = putStrLn -- fixme
      }

----------------------------------------------------------------

data HandshakeCheck = Start
                    | Cont !Word8 !Word32
                    | Done
                    deriving Show

handshakeCheck :: Word8 -> ByteString -> HandshakeCheck -> IO HandshakeCheck
handshakeCheck styp bs ck = withReadBuffer bs $ \rbuf -> loop rbuf ck
  where
    loop _    Done  = error "handshakeCheck Done"
    loop rbuf Start = do
        typ <- read8 rbuf
        len <- read24 rbuf
        rlen <- fromIntegral <$> remainingSize rbuf
        case rlen `compare` len of
          EQ | typ == styp -> return Done
             | otherwise   -> return Start
          GT | typ == styp -> error "handshakeCheck Start"
             | otherwise   -> ff rbuf (fromIntegral len) >> loop rbuf Start
          LT               -> return $ Cont typ (len - rlen)
    loop rbuf (Cont typ skipLen) = do
        rlen <- fromIntegral <$> remainingSize rbuf
        case rlen `compare` skipLen of
          EQ | typ == styp -> return Done
             | otherwise   -> return Start
          GT | typ == styp -> error "handshakeCheck Cont"
             | otherwise   -> ff rbuf (fromIntegral skipLen) >> loop rbuf Start
          LT               -> return $ Cont typ (skipLen - rlen)
