{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Crypto (
    setEncryptionLevel
  , getEncryptionLevel
  , checkEncryptionLevel
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
  ) where

import Control.Concurrent.STM
import Data.IORef
import Network.TLS.QUIC

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

setEncryptionLevel :: Connection -> EncryptionLevel -> IO ()
setEncryptionLevel conn@Connection{..} level = do
    (_, q) <- getSockInfo conn
    atomically $ do
        writeTVar encryptionLevel level
        case level of
          HandshakeLevel -> do
              readTVar (pendingQ ! RTT0Level)      >>= mapM_ (prependRecvQ q)
              readTVar (pendingQ ! HandshakeLevel) >>= mapM_ (prependRecvQ q)
          RTT1Level      ->
              readTVar (pendingQ ! RTT1Level)      >>= mapM_ (prependRecvQ q)
          _              -> return ()

getEncryptionLevel :: Connection -> IO EncryptionLevel
getEncryptionLevel Connection{..} = readTVarIO encryptionLevel

checkEncryptionLevel :: Connection -> EncryptionLevel -> CryptPacket -> IO Bool
checkEncryptionLevel Connection{..} level cpkt = atomically $ do
    l <- readTVar encryptionLevel
    if l >= level then
        return True
      else do
        modifyTVar' (pendingQ ! level) (cpkt :)
        return False

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

dropSecrets :: Connection -> IO ()
dropSecrets Connection{..} = do
    writeArray coders InitialLevel   initialCoder
    writeArray coders RTT0Level      initialCoder
    writeArray coders HandshakeLevel initialCoder

----------------------------------------------------------------

initializeCoder :: Connection -> EncryptionLevel -> TrafficSecrets a -> IO ()
initializeCoder conn lvl (ClientTrafficSecret c, ServerTrafficSecret s) = do
    let txSecret | isClient conn = Secret c
                 | otherwise     = Secret s
    let rxSecret | isClient conn = Secret s
                 | otherwise     = Secret c
    cipher <- getCipher conn lvl
    let txPayloadKey = aeadKey cipher txSecret
        txPayloadIV  = initialVector cipher txSecret
        txHeaderKey = headerProtectionKey cipher txSecret
        enc = encryptPayload cipher txPayloadKey txPayloadIV
        pro = protectionMask cipher txHeaderKey
    let rxPayloadKey = aeadKey cipher rxSecret
        rxPayloadIV  = initialVector cipher rxSecret
        rxHeaderKey = headerProtectionKey cipher rxSecret
        dec = decryptPayload cipher rxPayloadKey rxPayloadIV
        unp = protectionMask cipher rxHeaderKey
    let coder = Coder enc dec pro unp
    writeArray (coders conn) lvl coder

getCoder :: Connection -> EncryptionLevel -> IO Coder
getCoder conn lvl = readArray (coders conn) lvl
