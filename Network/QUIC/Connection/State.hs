{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.State (
    setConnection0RTTReady,
    isConnection1RTTReady,
    setConnection1RTTReady,
    isConnectionEstablished,
    setConnectionEstablished,
    isConnectionClosed,
    setConnectionClosed,
    wait0RTTReady,
    wait1RTTReady,
    waitEstablished,
    readConnectionFlowTx,
    addTxData,
    setTxMaxData,
    getRxMaxData,
    updateFlowRx,
    checkRxMaxData,
    addTxBytes,
    getTxBytes,
    addRxBytes,
    getRxBytes,
    setAddressValidated,
    waitAntiAmplificationFree,
    checkAntiAmplificationFree,
) where

import Control.Concurrent.STM
import Network.Control

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Recovery

----------------------------------------------------------------

setConnectionState :: Connection -> ConnectionState -> IO ()
setConnectionState Connection{..} st =
    atomically $ writeTVar (connectionState connState) st

setConnection0RTTReady :: Connection -> IO ()
setConnection0RTTReady conn = setConnectionState conn ReadyFor0RTT

setConnection1RTTReady :: Connection -> IO ()
setConnection1RTTReady conn = do
    setConnectionState conn ReadyFor1RTT
    writeIORef (shared1RTTReady $ shared conn) True

setConnectionEstablished :: Connection -> IO ()
setConnectionEstablished conn = setConnectionState conn Established

setConnectionClosed :: Connection -> IO ()
setConnectionClosed conn = setConnectionState conn Closed

----------------------------------------------------------------

isConnection1RTTReady :: Connection -> IO Bool
isConnection1RTTReady Connection{..} = atomically $ do
    st <- readTVar $ connectionState connState
    return (st >= ReadyFor1RTT && st /= Closed)

isConnectionClosed :: Connection -> IO Bool
isConnectionClosed Connection{..} = atomically $ do
    st <- readTVar $ connectionState connState
    return (st == Closed)

----------------------------------------------------------------

-- | Waiting until 0-RTT data can be sent.
wait0RTTReady :: Connection -> IO ()
wait0RTTReady Connection{..} = atomically $ do
    cs <- readTVar $ connectionState connState
    check (cs >= ReadyFor0RTT && cs /= Closed)

-- | Waiting until 1-RTT data can be sent.
wait1RTTReady :: Connection -> IO ()
wait1RTTReady Connection{..} = atomically $ do
    cs <- readTVar $ connectionState connState
    check (cs >= ReadyFor1RTT && cs /= Closed)

-- | For clients, waiting until HANDSHAKE_DONE is received.
--   For servers, waiting until a TLS stack reports that the handshake is complete.
waitEstablished :: Connection -> IO ()
waitEstablished Connection{..} = atomically $ do
    cs <- readTVar $ connectionState connState
    check (cs >= Established && cs /= Closed)

----------------------------------------------------------------

readConnectionFlowTx :: Connection -> STM TxFlow
readConnectionFlowTx Connection{..} = readTVar flowTx

----------------------------------------------------------------

addTxData :: Connection -> Int -> STM ()
addTxData Connection{..} n = modifyTVar' flowTx add
  where
    add flow = flow{txfSent = txfSent flow + n}

setTxMaxData :: Connection -> Int -> IO ()
setTxMaxData Connection{..} n = atomically $ modifyTVar' flowTx set
  where
    set flow
        | txfLimit flow < n = flow{txfLimit = n}
        | otherwise = flow

----------------------------------------------------------------

getRxMaxData :: Connection -> IO Int
getRxMaxData Connection{..} = rxfLimit <$> readIORef flowRx

updateFlowRx :: Connection -> Int -> IO (Maybe Int)
updateFlowRx Connection{..} consumed =
    atomicModifyIORef' flowRx $ maybeOpenRxWindow consumed FCTMaxData

checkRxMaxData :: Connection -> Int -> IO Bool
checkRxMaxData Connection{..} len =
    atomicModifyIORef' flowRx $ checkRxLimit len

----------------------------------------------------------------

addTxBytes :: Connection -> Int -> IO ()
addTxBytes Connection{..} n = atomically $ modifyTVar' bytesTx (+ n)

getTxBytes :: Connection -> IO Int
getTxBytes Connection{..} = readTVarIO bytesTx

addRxBytes :: Connection -> Int -> IO ()
addRxBytes Connection{..} n = atomically $ modifyTVar' bytesRx (+ n)

getRxBytes :: Connection -> IO Int
getRxBytes Connection{..} = readTVarIO bytesRx

----------------------------------------------------------------

setAddressValidated :: Connection -> IO ()
setAddressValidated Connection{..} = atomically $ writeTVar addressValidated True

-- Three times rule for anti amplification
waitAntiAmplificationFree :: Connection -> Int -> IO ()
waitAntiAmplificationFree conn@Connection{..} siz = do
    ok <- checkAntiAmplificationFree conn siz
    unless ok $ do
        beforeAntiAmp connLDCC
        atomically (checkAntiAmplificationFreeSTM conn siz >>= check)

-- setLossDetectionTimer is called eventually.

checkAntiAmplificationFreeSTM :: Connection -> Int -> STM Bool
checkAntiAmplificationFreeSTM Connection{..} siz = do
    validated <- readTVar addressValidated
    if validated
        then return True
        else do
            tx <- readTVar bytesTx
            rx <- readTVar bytesRx
            return (tx + siz <= 3 * rx)

checkAntiAmplificationFree :: Connection -> Int -> IO Bool
checkAntiAmplificationFree conn siz =
    atomically $ checkAntiAmplificationFreeSTM conn siz
