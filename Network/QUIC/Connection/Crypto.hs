{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Crypto (
    setEncryptionLevel
  , waitEncryptionLevel
  , putOffCrypto
  --
  , getCipher
  , setCipher
  , getTLSMode
  , getApplicationProtocol
  , setNegotiated
  --
  , dropSecrets
  --
  , initializeCoder
  , getCoder
  , getProtector
  ) where

import Control.Concurrent.STM
import Network.TLS.QUIC

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

setEncryptionLevel :: Connection -> EncryptionLevel -> IO ()
setEncryptionLevel conn@Connection{..} lvl = do
    (_, q) <- getSockInfo conn
    atomically $ do
        writeTVar (encryptionLevel connState) lvl
        case lvl of
          HandshakeLevel -> do
              readTVar (pendingQ ! RTT0Level)      >>= mapM_ (prependRecvQ q)
              readTVar (pendingQ ! HandshakeLevel) >>= mapM_ (prependRecvQ q)
          RTT1Level      ->
              readTVar (pendingQ ! RTT1Level)      >>= mapM_ (prependRecvQ q)
          _              -> return ()

putOffCrypto :: Connection -> EncryptionLevel -> ReceivedPacket -> IO ()
putOffCrypto Connection{..} lvl rpkt =
    atomically $ modifyTVar' (pendingQ ! lvl) (rpkt :)

waitEncryptionLevel :: Connection -> EncryptionLevel -> IO ()
waitEncryptionLevel Connection{..} lvl = atomically $ do
    l <- readTVar $ encryptionLevel connState
    check (l >= lvl)

----------------------------------------------------------------

getCipher :: Connection -> EncryptionLevel -> IO Cipher
getCipher Connection{..} lvl = readArray ciphers lvl

setCipher :: Connection -> EncryptionLevel -> Cipher -> IO ()
setCipher Connection{..} lvl cipher = writeArray ciphers lvl cipher

----------------------------------------------------------------

getTLSMode :: Connection -> IO HandshakeMode13
getTLSMode Connection{..} = handshakeMode <$> readIORef negotiated

getApplicationProtocol :: Connection -> IO (Maybe NegotiatedProtocol)
getApplicationProtocol Connection{..} = applicationProtocol <$> readIORef negotiated

setNegotiated :: Connection -> HandshakeMode13 -> Maybe NegotiatedProtocol -> ApplicationSecretInfo -> IO ()
setNegotiated Connection{..} mode mproto appSecInf =
    writeIORef negotiated Negotiated {
        handshakeMode = mode
      , applicationProtocol = mproto
      , applicationSecretInfo = appSecInf
      }

----------------------------------------------------------------

dropSecrets :: Connection -> EncryptionLevel -> IO ()
dropSecrets Connection{..} lvl = writeArray coders lvl initialCoder

----------------------------------------------------------------

initializeCoder :: Connection -> EncryptionLevel -> TrafficSecrets a -> IO ()
initializeCoder conn lvl sec = do
    cipher <- getCipher conn lvl
    let (coder, protector) = genCoder (isClient conn) cipher sec
    writeArray (coders conn) lvl coder
    writeArray (protectors conn) lvl protector

genCoder :: Bool -> Cipher -> TrafficSecrets a -> (Coder, Protector)
genCoder cli cipher (ClientTrafficSecret c, ServerTrafficSecret s) = (coder, protector)
  where
    txSecret | cli           = Secret c
             | otherwise     = Secret s
    rxSecret | cli           = Secret s
             | otherwise     = Secret c
    txPayloadKey = aeadKey cipher txSecret
    txPayloadIV  = initialVector cipher txSecret
    txHeaderKey  = headerProtectionKey cipher txSecret
    enc = encryptPayload cipher txPayloadKey txPayloadIV
    pro = protectionMask cipher txHeaderKey
    rxPayloadKey = aeadKey cipher rxSecret
    rxPayloadIV  = initialVector cipher rxSecret
    rxHeaderKey  = headerProtectionKey cipher rxSecret
    dec = decryptPayload cipher rxPayloadKey rxPayloadIV
    unp = protectionMask cipher rxHeaderKey
    coder = Coder enc dec
    protector = Protector pro unp

-- fixme
getCoder :: Connection -> EncryptionLevel -> IO Coder
getCoder conn lvl = readArray (coders conn) lvl

getProtector :: Connection -> EncryptionLevel -> IO Protector
getProtector conn lvl = readArray (protectors conn) lvl
