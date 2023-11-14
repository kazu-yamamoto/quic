{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.State (
    setConnection0RTTReady,
    isConnection1RTTReady,
    setConnection1RTTReady,
    isConnectionEstablished,
    setConnectionEstablished,
    wait0RTTReady,
    wait1RTTReady,
    waitEstablished,
    readConnectionFlowTx,
    addTxData,
    getTxData,
    setTxMaxData,
    getTxMaxData,
    addRxData,
    getRxData,
    addRxMaxData,
    getRxMaxData,
    getRxDataWindow,
    checkRxMaxData,
    addTxBytes,
    getTxBytes,
    addRxBytes,
    getRxBytes,
    setAddressValidated,
    waitAntiAmplificationFree,
    checkAntiAmplificationFree,
) where

import UnliftIO.STM

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Recovery
import Network.QUIC.Stream

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

----------------------------------------------------------------

isConnection1RTTReady :: Connection -> IO Bool
isConnection1RTTReady Connection{..} = atomically $ do
    st <- readTVar $ connectionState connState
    return (st >= ReadyFor1RTT)

----------------------------------------------------------------

-- | Waiting until 0-RTT data can be sent.
wait0RTTReady :: Connection -> IO ()
wait0RTTReady Connection{..} = atomically $ do
    cs <- readTVar $ connectionState connState
    checkSTM (cs >= ReadyFor0RTT)

-- | Waiting until 1-RTT data can be sent.
wait1RTTReady :: Connection -> IO ()
wait1RTTReady Connection{..} = atomically $ do
    cs <- readTVar $ connectionState connState
    checkSTM (cs >= ReadyFor1RTT)

-- | For clients, waiting until HANDSHAKE_DONE is received.
--   For servers, waiting until a TLS stack reports that the handshake is complete.
waitEstablished :: Connection -> IO ()
waitEstablished Connection{..} = atomically $ do
    cs <- readTVar $ connectionState connState
    checkSTM (cs >= Established)

----------------------------------------------------------------

readConnectionFlowTx :: Connection -> STM Flow
readConnectionFlowTx Connection{..} = readTVar flowTx

----------------------------------------------------------------

addTxData :: Connection -> Int -> STM ()
addTxData Connection{..} n = modifyTVar' flowTx add
  where
    add flow = flow{flowData = flowData flow + n}

getTxData :: Connection -> IO Int
getTxData Connection{..} = atomically $ flowData <$> readTVar flowTx

setTxMaxData :: Connection -> Int -> IO ()
setTxMaxData Connection{..} n = atomically $ modifyTVar' flowTx set
  where
    set flow
        | flowMaxData flow < n = flow{flowMaxData = n}
        | otherwise = flow

getTxMaxData :: Connection -> STM Int
getTxMaxData Connection{..} = flowMaxData <$> readTVar flowTx

----------------------------------------------------------------

addRxData :: Connection -> Int -> IO ()
addRxData Connection{..} n = atomicModifyIORef'' flowRx add
  where
    add flow = flow{flowData = flowData flow + n}

getRxData :: Connection -> IO Int
getRxData Connection{..} = flowData <$> readIORef flowRx

addRxMaxData :: Connection -> Int -> IO Int
addRxMaxData Connection{..} n = atomicModifyIORef' flowRx add
  where
    add flow = (flow{flowMaxData = m}, m)
      where
        m = flowMaxData flow + n

getRxMaxData :: Connection -> IO Int
getRxMaxData Connection{..} = flowMaxData <$> readIORef flowRx

getRxDataWindow :: Connection -> IO Int
getRxDataWindow Connection{..} = flowWindow <$> readIORef flowRx

----------------------------------------------------------------

checkRxMaxData :: Connection -> Int -> IO Bool
checkRxMaxData Connection{..} len = do
    received <- readIORef flowBytesRx
    maxData <- flowMaxData <$> readIORef flowRx
    if received + len < maxData
        then do
            modifyIORef' flowBytesRx (+ len)
            return True
        else return False

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
        atomically (checkAntiAmplificationFreeSTM conn siz >>= checkSTM)

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
