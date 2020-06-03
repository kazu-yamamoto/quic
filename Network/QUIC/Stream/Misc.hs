{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Misc (
    getStreamTxOffset
  , isStreamTxClosed
  , setStreamTxFin
  , getStreamRxOffset
  , isStreamRxClosed
  , setStreamRxFin
  --
  , addTxStreamData
  , setTxMaxStreamData
  , addRxStreamData
  , setRxMaxStreamData
  , addRxMaxStreamData
  , getRxStreamWindow
  -- Shared
  , isTxClosed
  , isRxClosed
  , get1RTTReady
  , set1RTTReady
  --
  , waitWindowIsOpen
  , flowWindow
  ) where

import Control.Concurrent.STM
import Data.IORef

import Network.QUIC.Imports
import Network.QUIC.Stream.Types

----------------------------------------------------------------

getStreamTxOffset :: Stream -> Int -> IO Offset
getStreamTxOffset Stream{..} len = atomicModifyIORef' streamStateTx get
  where
    get (StreamState off fin) = (StreamState (off + len) fin, off)

isStreamTxClosed :: Stream -> IO Bool
isStreamTxClosed Stream{..} = do
    StreamState _ fin <- readIORef streamStateTx
    return fin

setStreamTxFin :: Stream -> IO ()
setStreamTxFin Stream{..} = atomicModifyIORef' streamStateTx set
  where
    set (StreamState off _) = (StreamState off True, ())

----------------------------------------------------------------

getStreamRxOffset :: Stream -> Int -> IO Offset
getStreamRxOffset Stream{..} len = atomicModifyIORef' streamStateRx get
  where
    get (StreamState off fin) = (StreamState (off + len) fin, off)

isStreamRxClosed :: Stream -> IO Bool
isStreamRxClosed Stream{..} = do
    StreamState _ fin <- readIORef streamStateRx
    return fin

setStreamRxFin :: Stream -> IO ()
setStreamRxFin Stream{..} = atomicModifyIORef' streamStateRx set
  where
    set (StreamState off _) = (StreamState off True, ())

----------------------------------------------------------------

addTxStreamData :: Stream -> Int -> IO ()
addTxStreamData Stream{..} n = atomically $ modifyTVar' streamFlowTx add
  where
    add flow = flow { flowData = flowData flow + n }

setTxMaxStreamData :: Stream -> Int -> IO ()
setTxMaxStreamData Stream{..} n = atomically $ modifyTVar' streamFlowTx
    $ \flow -> flow { flowMaxData = n }

----------------------------------------------------------------

addRxStreamData :: Stream -> Int -> IO ()
addRxStreamData Stream{..} n = atomicModifyIORef' streamFlowRx add
  where
    add flow = (flow { flowData = flowData flow + n }, ())

setRxMaxStreamData :: Stream -> Int -> IO ()
setRxMaxStreamData Stream{..} n = atomicModifyIORef' streamFlowRx
    $ \flow -> (flow { flowMaxData = n }, ())

addRxMaxStreamData :: Stream -> Int -> IO Int
addRxMaxStreamData Stream{..} n = atomicModifyIORef' streamFlowRx add
  where
    add flow = (flow { flowMaxData = m }, m)
      where
        m = flowMaxData flow + n

getRxStreamWindow :: Stream -> IO Int
getRxStreamWindow Stream{..} = flowWindow <$> readIORef streamFlowRx

----------------------------------------------------------------

isTxClosed :: Stream -> IO Bool
isTxClosed Stream{..} = readIORef $ sharedCloseSent streamShared

isRxClosed :: Stream -> IO Bool
isRxClosed Stream{..} = readIORef $ sharedCloseReceived streamShared

----------------------------------------------------------------

get1RTTReady :: Stream -> IO Bool
get1RTTReady Stream{..} = readIORef $ shared1RTTReady streamShared

set1RTTReady :: Stream -> IO ()
set1RTTReady Stream{..} = atomicWriteIORef (shared1RTTReady streamShared) True

----------------------------------------------------------------

flowWindow :: Flow -> Int
flowWindow Flow{..} = flowMaxData - flowData

waitWindowIsOpen :: Stream -> Int -> IO ()
waitWindowIsOpen Stream{..} n = do
  atomically $ do
    strmWindow <- flowWindow <$> readTVar streamFlowTx
    check (strmWindow >= n)
    connWindow <- flowWindow <$> readTVar (sharedConnFlowTx streamShared)
    check (connWindow >= n)
