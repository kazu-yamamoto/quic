{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.State (
    isConnectionOpen
  , setConnection0RTTReady
  , isConnection1RTTReady
  , setConnection1RTTReady
  , isConnectionEstablished
  , setConnectionEstablished
  , isCloseSent
  , setCloseSent
  , isCloseReceived
  , setCloseReceived
  , wait0RTTReady
  , wait1RTTReady
  , waitEstablished
  , waitClosed
  , addTxData
  , getTxData
  , setTxMaxData
  , getTxMaxData
  , addRxData
  , getRxData
  , addRxMaxData
  , getRxDataWindow
  ) where

import Control.Concurrent.STM
import Data.IORef

import Network.QUIC.Connection.Types
import Network.QUIC.Stream

----------------------------------------------------------------

setConnectionState :: Connection -> ConnectionState -> IO ()
setConnectionState Connection{..} st =
    atomically $ writeTVar connectionState st

setConnection0RTTReady :: Connection -> IO ()
setConnection0RTTReady conn = setConnectionState conn ReadyFor0RTT

setConnection1RTTReady :: Connection -> IO ()
setConnection1RTTReady conn = do
    setConnectionState conn ReadyFor1RTT
    writeIORef (shared1RTTReady $ shared conn) True

setConnectionEstablished :: Connection -> IO ()
setConnectionEstablished conn = setConnectionState conn Established

----------------------------------------------------------------

isConnectionEstablished :: Connection -> IO Bool
isConnectionEstablished Connection{..} = atomically $ do
    st <- readTVar connectionState
    case st of
      Established -> return True
      Closing _   -> return True
      _           -> return False

isConnectionOpen :: Connection -> IO Bool
isConnectionOpen Connection{..} = atomically $ do
    st <- readTVar connectionState
    case st of
      Closing _ -> return False
      _         -> return True

isConnection1RTTReady :: Connection -> IO Bool
isConnection1RTTReady Connection{..} = atomically $ do
    st <- readTVar connectionState
    return (st >= ReadyFor1RTT)

----------------------------------------------------------------

setCloseSent :: Connection -> IO ()
setCloseSent Connection{..} = do
    atomically $ modifyTVar connectionState modify
    writeIORef (sharedCloseSent shared) True
  where
    modify (Closing cs) = Closing $ cs { closeSent = True }
    modify _            = Closing $ CloseState { closeSent = True
                                               , closeReceived = False }

setCloseReceived :: Connection -> IO ()
setCloseReceived Connection{..} = do
    atomically $ modifyTVar connectionState modify
    writeIORef (sharedCloseReceived shared) True
  where
    modify (Closing cs) = Closing $ cs { closeReceived = True }
    modify _            = Closing $ CloseState { closeSent = False
                                               , closeReceived = True }

isCloseSent :: Connection -> IO Bool
isCloseSent Connection{..} = atomically (chk <$> readTVar connectionState)
  where
    chk (Closing cs) = closeSent cs
    chk _            = False

isCloseReceived :: Connection -> IO Bool
isCloseReceived Connection{..} = atomically (chk <$> readTVar connectionState)
  where
    chk (Closing cs) = closeReceived cs
    chk _            = False

wait0RTTReady :: Connection -> IO ()
wait0RTTReady Connection{..} = atomically $ do
    cs <- readTVar connectionState
    check (cs >= ReadyFor0RTT)

wait1RTTReady :: Connection -> IO ()
wait1RTTReady Connection{..} = atomically $ do
    cs <- readTVar connectionState
    check (cs >= ReadyFor1RTT)

waitEstablished :: Connection -> IO ()
waitEstablished Connection{..} = atomically $ do
    cs <- readTVar connectionState
    check (cs >= Established)

waitClosed :: Connection -> IO ()
waitClosed Connection{..} = atomically $ do
    cs <- readTVar connectionState
    check (cs == Closing (CloseState True True))

----------------------------------------------------------------

addTxData :: Connection -> Int -> IO ()
addTxData Connection{..} n = atomically $ modifyTVar' flowTx add
  where
    add flow = flow { flowData = flowData flow + n }

getTxData :: Connection -> IO Int
getTxData Connection{..} = atomically $ flowData <$> readTVar flowTx

setTxMaxData :: Connection -> Int -> IO ()
setTxMaxData Connection{..} n = atomically $ modifyTVar' flowTx set
  where
    set flow = flow { flowMaxData = n }

getTxMaxData :: Connection -> STM Int
getTxMaxData Connection{..} = flowMaxData <$> readTVar flowTx

----------------------------------------------------------------

addRxData :: Connection -> Int -> IO ()
addRxData Connection{..} n = atomicModifyIORef' flowRx add
  where
    add flow = (flow { flowData = flowData flow + n }, ())

getRxData :: Connection -> IO Int
getRxData Connection{..} = flowData <$> readIORef flowRx

addRxMaxData :: Connection -> Int -> IO Int
addRxMaxData Connection{..} n = atomicModifyIORef' flowRx add
  where
    add flow = (flow { flowMaxData = m }, m)
      where
        m = flowMaxData flow + n

getRxDataWindow :: Connection -> IO Int
getRxDataWindow Connection{..} = flowWindow <$> readIORef flowRx
