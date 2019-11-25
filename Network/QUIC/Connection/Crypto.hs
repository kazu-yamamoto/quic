{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Crypto where

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

getCipher :: Connection -> IO Cipher
getCipher Connection{..} = readIORef usedCipher

setCipher :: Connection -> Cipher -> IO ()
setCipher Connection{..} cipher = writeIORef usedCipher cipher

setPeerParameters :: Connection -> ParametersList -> IO ()
setPeerParameters Connection{..} plist = do
    def <- readIORef peerParams
    writeIORef peerParams $ updateParameters def plist

setNegotiatedProto :: Connection -> Maybe ByteString -> IO ()
setNegotiatedProto Connection{..} malpn = writeIORef negotiatedProto malpn

----------------------------------------------------------------

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

txInitialSecret :: Connection -> IO Secret
txInitialSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ iniSecrets conn
    return $ Secret $ if isClient conn then c else s

rxInitialSecret :: Connection -> IO Secret
rxInitialSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ iniSecrets conn
    return $ Secret $ if isClient conn then s else c

txHandshakeSecret :: Connection -> IO Secret
txHandshakeSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ hndSecrets conn
    return $ Secret $ if isClient conn then c else s

rxHandshakeSecret :: Connection -> IO Secret
rxHandshakeSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ hndSecrets conn
    return $ Secret $ if isClient conn then s else c

txApplicationSecret :: Connection -> IO Secret
txApplicationSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ appSecrets conn
    return $ Secret $ if isClient conn then c else s

rxApplicationSecret :: Connection -> IO Secret
rxApplicationSecret conn = do
    (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef $ appSecrets conn
    return $ Secret $ if isClient conn then s else c

----------------------------------------------------------------

modifyCryptoOffset :: Connection -> PacketType -> Offset -> IO Offset
modifyCryptoOffset conn pt len = atomicModifyIORef' ref modify
  where
    ref = getCryptoOffset conn pt
    modify off = (off + len, off)

getCryptoOffset :: Connection -> PacketType -> IORef Offset
getCryptoOffset conn Initial   = iniCryptoOffset conn
getCryptoOffset conn Handshake = hndCryptoOffset conn
getCryptoOffset conn Short     = appCryptoOffset conn
getCryptoOffset _   _          = error "getCryptoOffset"
