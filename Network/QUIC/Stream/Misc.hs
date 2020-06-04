{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Misc (
    getStreamTxOffset
  , isStreamTxClosed
  , setStreamTxFin
  , getStreamRxOffset
  , isStreamRxClosed
  , setStreamRxFin
  --
  , isTxClosed
  , isRxClosed
  --
  , addTxStreamData
  , setTxMaxStreamData
  , getRxStreamData
  , addRxStreamData
  , getRxMaxStreamData
  , setRxMaxStreamData
  , addRxMaxStreamData
  , waitWindowIsOpen
  , get1RTTReady
  , set1RTTReady
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

isTxClosed :: Stream -> IO Bool
isTxClosed Stream{..} = readIORef $ sharedCloseSent streamShared

isRxClosed :: Stream -> IO Bool
isRxClosed Stream{..} = readIORef $ sharedCloseReceived streamShared

addTxStreamData :: Stream -> Int -> IO ()
addTxStreamData Stream{..} n = atomically $ modifyTVar' streamFlowTx add
  where
    add flow = flow { flowData = flowData flow + n }

setTxMaxStreamData :: Stream -> Int -> IO ()
setTxMaxStreamData Stream{..} n = atomically $ modifyTVar' streamFlowTx
    $ \flow -> flow { flowMaxData = n }

----------------------------------------------------------------

getRxStreamData :: Stream -> IO Int
getRxStreamData Stream{..} = flowData <$> readIORef streamFlowRx

addRxStreamData :: Stream -> Int -> IO ()
addRxStreamData Stream{..} n = atomicModifyIORef' streamFlowRx add
  where
    add flow = (flow { flowData = flowData flow + n }, ())

getRxMaxStreamData :: Stream -> IO Int
getRxMaxStreamData Stream{..} = flowMaxData <$> readIORef streamFlowRx

setRxMaxStreamData :: Stream -> Int -> IO ()
setRxMaxStreamData Stream{..} n = atomicModifyIORef' streamFlowRx
    $ \flow -> (flow { flowMaxData = n }, ())

addRxMaxStreamData :: Stream -> Int -> IO ()
addRxMaxStreamData Stream{..} n = atomicModifyIORef' streamFlowRx
    $ \flow -> (flow { flowMaxData = flowMaxData flow + n }, ())

----------------------------------------------------------------

get1RTTReady :: Stream -> IO Bool
get1RTTReady Stream{..} = readIORef $ shared1RTTReady streamShared

set1RTTReady :: Stream -> IO ()
set1RTTReady Stream{..} = atomicWriteIORef (shared1RTTReady streamShared) True

----------------------------------------------------------------

window :: Flow -> Int
window Flow{..} = flowMaxData - flowData

waitWindowIsOpen :: Stream -> Int -> IO ()
waitWindowIsOpen Stream{..} n = do
{-
  xy <- atomically $ do
      x <- readTVar streamFlowTx
      y <- readTVar (sharedConnFlowTx streamShared)
      return (x,y)
  print xy
-}
  atomically $ do
    strmWindow <- window <$> readTVar streamFlowTx
    check (strmWindow >= n)
    connWindow <- window <$> readTVar (sharedConnFlowTx streamShared)
    check (connWindow >= n)
