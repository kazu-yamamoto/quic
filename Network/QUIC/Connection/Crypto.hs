{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Crypto (
    checkEncryptionLevel
  --
  , getClientController
  , setClientController
  , clearClientController
  --
  , getCipher
  , setCipher
  --
  , getPeerParameters
  , setPeerParameters
  , setNegotiatedProto
  --
  , getTxSecret
  , getRxSecret
  , setEarlySecret
  , setInitialSecrets
  , setHandshakeSecrets
  , setApplicationSecrets
  --
  , modifyCryptoOffset
  , setCryptoOffset
  ) where

import Control.Concurrent.STM
import Data.IORef
import Network.TLS.QUIC

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

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
getCipher _ InitialLevel   = return defaultCipher
getCipher Connection{..} _ = readIORef usedCipher

setCipher :: Connection -> Cipher -> IO ()
setCipher Connection{..} cipher = writeIORef usedCipher cipher

getPeerParameters :: Connection -> IO Parameters
getPeerParameters Connection{..} = readIORef peerParams

setPeerParameters :: Connection -> ParametersList -> IO ()
setPeerParameters Connection{..} plist = do
    def <- readIORef peerParams
    writeIORef peerParams $ updateParameters def plist

setNegotiatedProto :: Connection -> Maybe ByteString -> IO ()
setNegotiatedProto Connection{..} malpn = writeIORef negotiatedProto malpn

----------------------------------------------------------------

setEarlySecret :: Connection -> Maybe (ClientTrafficSecret EarlySecret) -> IO ()
setEarlySecret Connection{..} msec = writeIORef earlySecret msec

setInitialSecrets :: Connection -> TrafficSecrets InitialSecret -> IO ()
setInitialSecrets Connection{..} secs = writeIORef iniSecrets secs

setHandshakeSecrets :: Connection -> TrafficSecrets HandshakeSecret -> IO ()
setHandshakeSecrets Connection{..} secs = do
    writeIORef hndSecrets secs
    atomically $ writeTVar encryptionLevel HandshakeLevel

setApplicationSecrets :: Connection -> TrafficSecrets ApplicationSecret -> IO ()
setApplicationSecrets Connection{..} secs = do
    writeIORef appSecrets secs
    atomically $ writeTVar encryptionLevel RTT1Level

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
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ iniSecrets conn
    return $ Secret $ if isClient conn then c else s

rxInitialSecret :: Connection -> IO Secret
rxInitialSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ iniSecrets conn
    return $ Secret $ if isClient conn then s else c

----------------------------------------------------------------

xEarlySecret :: Connection -> IO Secret
xEarlySecret conn = do
    mc <- readIORef (earlySecret conn)
    case mc of
      Nothing                      -> return $ Secret ""
      Just (ClientTrafficSecret c) -> return $ Secret c

----------------------------------------------------------------

txHandshakeSecret :: Connection -> IO Secret
txHandshakeSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ hndSecrets conn
    return $ Secret $ if isClient conn then c else s

rxHandshakeSecret :: Connection -> IO Secret
rxHandshakeSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ hndSecrets conn
    return $ Secret $ if isClient conn then s else c

----------------------------------------------------------------

txApplicationSecret :: Connection -> IO Secret
txApplicationSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ appSecrets conn
    return $ Secret $ if isClient conn then c else s

rxApplicationSecret :: Connection -> IO Secret
rxApplicationSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ appSecrets conn
    return $ Secret $ if isClient conn then s else c

----------------------------------------------------------------

setCryptoOffset :: Connection -> EncryptionLevel -> Offset -> IO ()
setCryptoOffset conn lvl len = writeIORef ref len
  where
    ref = getCryptoOffset conn lvl

modifyCryptoOffset :: Connection -> EncryptionLevel -> Offset -> IO Offset
modifyCryptoOffset conn lvl len = atomicModifyIORef' ref modify
  where
    ref = getCryptoOffset conn lvl
    modify off = (off + len, off)

getCryptoOffset :: Connection -> EncryptionLevel -> IORef Offset
getCryptoOffset conn InitialLevel   = iniCryptoOffset conn
getCryptoOffset _    RTT0Level      = error "getCryptoOffset"
getCryptoOffset conn HandshakeLevel = hndCryptoOffset conn
getCryptoOffset conn RTT1Level      = appCryptoOffset conn
