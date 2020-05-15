{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Crypto (
    setEncryptionLevel
  , getEncryptionLevel
  , checkEncryptionLevel
  --
  , getPeerParameters
  , setPeerParameters
  --
  , getCipher
  , getTLSMode
  , setTLSMode
  , getApplicationProtocol
  , setApplicationProtocol
  --
  , getTxSecret
  , getRxSecret
  , setInitialSecrets
  --
  , getEarlySecretInfo
  , getHandshakeSecretInfo
  , getApplicationSecretInfo
  , setEarlySecretInfo
  , setHandshakeSecretInfo
  , setApplicationSecretInfo
  --
  , dropSecrets
  ) where

import Control.Concurrent.STM
import Data.IORef
import Network.TLS.QUIC

import Network.QUIC.Connection.Types
import Network.QUIC.Connection.Misc
import Network.QUIC.Parameters
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
              reverse <$> readTVar pendingRTT0      >>= mapM_ (prependRecvQ q)
              reverse <$> readTVar pendingHandshake >>= mapM_ (prependRecvQ q)
          RTT1Level      ->
              reverse <$> readTVar pendingRTT1      >>= mapM_ (prependRecvQ q)
          _              -> return ()

getEncryptionLevel :: Connection -> IO EncryptionLevel
getEncryptionLevel Connection{..} = readTVarIO encryptionLevel

checkEncryptionLevel :: Connection -> EncryptionLevel -> CryptPacket -> IO Bool
checkEncryptionLevel Connection{..} level cpkt = atomically $ do
    l <- readTVar encryptionLevel
    if l >= level then
        return True
      else do
        case level of
          RTT0Level      -> modifyTVar' pendingRTT0 (cpkt :)
          HandshakeLevel -> modifyTVar' pendingHandshake (cpkt :)
          RTT1Level      -> modifyTVar' pendingRTT1 (cpkt :)
          _              -> return ()
        return False

----------------------------------------------------------------

getCipher :: Connection -> EncryptionLevel -> IO Cipher
getCipher _ InitialLevel = return defaultCipher
getCipher Connection{..} RTT0Level = do
    EarlySecretInfo cipher _ <- readIORef elySecInfo
    return cipher
getCipher Connection{..} _ = do
    HandshakeSecretInfo cipher _ <- readIORef hndSecInfo
    return cipher

setEarlySecretInfo :: Connection -> Maybe EarlySecretInfo -> IO ()
setEarlySecretInfo _ Nothing = return ()
setEarlySecretInfo Connection{..} (Just info) = atomicWriteIORef elySecInfo info

setHandshakeSecretInfo :: Connection -> HandshakeSecretInfo -> IO ()
setHandshakeSecretInfo Connection{..} = atomicWriteIORef hndSecInfo

setApplicationSecretInfo :: Connection -> ApplicationSecretInfo -> IO ()
setApplicationSecretInfo Connection{..} = atomicWriteIORef appSecInfo

getEarlySecretInfo :: Connection -> IO EarlySecretInfo
getEarlySecretInfo Connection{..} = readIORef elySecInfo

getHandshakeSecretInfo :: Connection -> IO HandshakeSecretInfo
getHandshakeSecretInfo Connection{..} = readIORef hndSecInfo

getApplicationSecretInfo :: Connection -> IO ApplicationSecretInfo
getApplicationSecretInfo Connection{..} = readIORef appSecInfo

----------------------------------------------------------------

getPeerParameters :: Connection -> IO Parameters
getPeerParameters Connection{..} = readIORef peerParams

setPeerParameters :: Connection -> ParametersList -> IO ()
setPeerParameters Connection{..} plist =
    modifyIORef peerParams $ \def -> updateParameters def plist

----------------------------------------------------------------

getTLSMode :: Connection -> IO HandshakeMode13
getTLSMode Connection{..} = readIORef hndMode

setTLSMode :: Connection -> HandshakeMode13 -> IO ()
setTLSMode Connection{..} = writeIORef hndMode

getApplicationProtocol :: Connection -> IO (Maybe NegotiatedProtocol)
getApplicationProtocol Connection{..} = readIORef appProto

setApplicationProtocol :: Connection -> Maybe NegotiatedProtocol -> IO ()
setApplicationProtocol Connection{..} = writeIORef appProto

----------------------------------------------------------------

setInitialSecrets :: Connection -> TrafficSecrets InitialSecret -> IO ()
setInitialSecrets Connection{..} secs = writeIORef iniSecrets secs

----------------------------------------------------------------

getTxSecret :: Connection -> EncryptionLevel -> IO Secret
getTxSecret conn InitialLevel   = txInitialSecret     conn
getTxSecret conn RTT0Level      =  xEarlySecret       conn
getTxSecret conn HandshakeLevel = txHandshakeSecret   conn
getTxSecret conn RTT1Level      = txApplicationSecret conn

getRxSecret :: Connection -> EncryptionLevel -> IO Secret
getRxSecret conn InitialLevel   = rxInitialSecret     conn
getRxSecret conn RTT0Level      =  xEarlySecret       conn
getRxSecret conn HandshakeLevel = rxHandshakeSecret   conn
getRxSecret conn RTT1Level      = rxApplicationSecret conn

----------------------------------------------------------------

txInitialSecret :: Connection -> IO Secret
txInitialSecret conn = do
    (c,s) <- xInitialSecret conn
    return $ if isClient conn then c else s

rxInitialSecret :: Connection -> IO Secret
rxInitialSecret conn = do
    (c,s) <- xInitialSecret conn
    return $ if isClient conn then s else c

xInitialSecret :: Connection -> IO (Secret, Secret)
xInitialSecret Connection{..} = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef iniSecrets
    return (Secret c, Secret s)

----------------------------------------------------------------

xEarlySecret :: Connection -> IO Secret
xEarlySecret Connection{..} = do
    (EarlySecretInfo _ (ClientTrafficSecret c)) <- readIORef elySecInfo
    return $ Secret c

----------------------------------------------------------------

txHandshakeSecret :: Connection -> IO Secret
txHandshakeSecret conn = do
    (c,s) <- xHandshakeSecret conn
    return $ if isClient conn then c else s

rxHandshakeSecret :: Connection -> IO Secret
rxHandshakeSecret conn = do
    (c,s) <- xHandshakeSecret conn
    return $ if isClient conn then s else c

xHandshakeSecret :: Connection -> IO (Secret, Secret)
xHandshakeSecret Connection{..} = do
    HandshakeSecretInfo _ (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef hndSecInfo
    return (Secret c, Secret s)

----------------------------------------------------------------

txApplicationSecret :: Connection -> IO Secret
txApplicationSecret conn = do
    (c,s) <- xApplicationSecret conn
    return $ if isClient conn then c else s

rxApplicationSecret :: Connection -> IO Secret
rxApplicationSecret conn = do
    (c,s) <- xApplicationSecret conn
    return $ if isClient conn then s else c

xApplicationSecret :: Connection -> IO (Secret, Secret)
xApplicationSecret Connection{..} = do
    ApplicationSecretInfo (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef appSecInfo
    return (Secret c, Secret s)

----------------------------------------------------------------

dropSecrets :: Connection -> IO ()
dropSecrets Connection{..} = do
    writeIORef iniSecrets defaultTrafficSecrets
    atomicWriteIORef elySecInfo (EarlySecretInfo defaultCipher (ClientTrafficSecret ""))
    atomicModifyIORef' hndSecInfo $ \(HandshakeSecretInfo cipher _) ->
        (HandshakeSecretInfo cipher defaultTrafficSecrets, ())
