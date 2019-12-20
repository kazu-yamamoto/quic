{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Crypto (
    setEncryptionLevel
  , checkEncryptionLevel
  --
  , getClientController
  , setClientController
  , clearClientController
  --
  , getPeerParameters
  , setPeerParameters
  --
  , getCipher
  , getTLSMode
  --
  , getTxSecret
  , getRxSecret
  , setInitialSecrets
  --
  , setEarlySecretInfo
  , setHandshakeSecretInfo
  , setApplicationSecretInfo
  ) where

import Control.Concurrent.STM
import Data.IORef
import Network.TLS.QUIC

import Network.QUIC.Connection.Types
import Network.QUIC.Parameters
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

setEncryptionLevel :: Connection -> EncryptionLevel -> IO ()
setEncryptionLevel Connection{..} level =
    atomically $ writeTVar encryptionLevel level

checkEncryptionLevel :: Connection -> EncryptionLevel -> IO ()
checkEncryptionLevel Connection{..} level = atomically $ do
    l <- readTVar encryptionLevel
    check (l >= level)

----------------------------------------------------------------

setClientController :: Connection -> ClientController -> IO ()
setClientController Connection{..} ctl = writeIORef connClientCntrl ctl

getClientController :: Connection -> IO ClientController
getClientController Connection{..} = readIORef connClientCntrl

clearClientController :: Connection -> IO ()
clearClientController conn = setClientController conn nullClientController

----------------------------------------------------------------

getCipher :: Connection -> EncryptionLevel -> IO Cipher
getCipher _ InitialLevel = return defaultCipher
getCipher Connection{..} RTT0Level = do
    Just (EarlySecretInfo cipher _) <- readIORef elySecInfo
    return cipher
getCipher Connection{..} _ = do
    Just (HandshakeSecretInfo cipher _) <- readIORef hndSecInfo
    return cipher

setEarlySecretInfo :: Connection -> Maybe EarlySecretInfo -> IO ()
setEarlySecretInfo Connection{..} minfo = writeIORef elySecInfo minfo

setHandshakeSecretInfo :: Connection -> HandshakeSecretInfo -> IO ()
setHandshakeSecretInfo Connection{..} info = writeIORef hndSecInfo $ Just info

setApplicationSecretInfo :: Connection -> ApplicationSecretInfo -> IO ()
setApplicationSecretInfo Connection{..} info = writeIORef appSecInfo $ Just info

----------------------------------------------------------------

getPeerParameters :: Connection -> IO Parameters
getPeerParameters Connection{..} = readIORef peerParams

setPeerParameters :: Connection -> ParametersList -> IO ()
setPeerParameters Connection{..} plist = do
    def <- readIORef peerParams
    writeIORef peerParams $ updateParameters def plist

----------------------------------------------------------------

getTLSMode :: Connection -> IO HandshakeMode13
getTLSMode Connection{..} = do
    minfo <- readIORef $ appSecInfo
    case minfo of
      Nothing -> error "getTLSMode"
      Just (ApplicationSecretInfo mode _ _) -> return mode

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
    minfo <- readIORef elySecInfo
    case minfo of
      Nothing                                          -> return $ Secret ""
      Just (EarlySecretInfo _ (ClientTrafficSecret c)) -> return $ Secret c

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
    minfo <- readIORef $ hndSecInfo
    case minfo of
      Nothing -> return (Secret "", Secret "")
      Just (HandshakeSecretInfo _ (ClientTrafficSecret c, ServerTrafficSecret s)) -> return (Secret c, Secret s)

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
    minfo <- readIORef $ appSecInfo
    case minfo of
      Nothing -> return (Secret "", Secret "")
      Just (ApplicationSecretInfo _ _ (ClientTrafficSecret c, ServerTrafficSecret s)) -> return (Secret c, Secret s)
