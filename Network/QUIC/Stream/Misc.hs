{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Misc (
    getTxStreamOffset
  , isTxStreamClosed
  , setTxStreamFin
  , getRxStreamOffset
  , isRxStreamClosed
  , setRxStreamFin
  --
  , addTxStreamData
  , setTxMaxStreamData
  , addRxStreamData
  , setRxMaxStreamData
  , addRxMaxStreamData
  , getRxStreamWindow
  -- Shared
  , isClosed
  , is1RTTReady
  --
  , waitWindowIsOpen
  , flowWindow
  ) where

import Control.Concurrent.STM
import Data.IORef

import Network.QUIC.Imports
import Network.QUIC.Stream.Types

----------------------------------------------------------------

getTxStreamOffset :: Stream -> Int -> IO Offset
getTxStreamOffset Stream{..} len = atomicModifyIORef' streamStateTx get
  where
    get (StreamState off fin) = (StreamState (off + len) fin, off)

isTxStreamClosed :: Stream -> IO Bool
isTxStreamClosed Stream{..} = do
    StreamState _ fin <- readIORef streamStateTx
    return fin

setTxStreamFin :: Stream -> IO ()
setTxStreamFin Stream{..} = atomicModifyIORef' streamStateTx set
  where
    set (StreamState off _) = (StreamState off True, ())

----------------------------------------------------------------

getRxStreamOffset :: Stream -> Int -> IO Offset
getRxStreamOffset Stream{..} len = atomicModifyIORef' streamStateRx get
  where
    get (StreamState off fin) = (StreamState (off + len) fin, off)

isRxStreamClosed :: Stream -> IO Bool
isRxStreamClosed Stream{..} = do
    StreamState _ fin <- readIORef streamStateRx
    return fin

setRxStreamFin :: Stream -> IO ()
setRxStreamFin Stream{..} = atomicModifyIORef' streamStateRx set
  where
    set (StreamState off _) = (StreamState off True, ())

----------------------------------------------------------------

addTxStreamData :: Stream -> Int -> IO ()
addTxStreamData Stream{..} n = atomically $ modifyTVar' streamFlowTx add
  where
    add flow = flow { flowData = flowData flow + n }

setTxMaxStreamData :: Stream -> Int -> IO ()
setTxMaxStreamData Stream{..} n = atomically $ modifyTVar' streamFlowTx set
  where
    set flow
     | flowMaxData flow < n = flow { flowMaxData = n }
     |otherwise             = flow

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

isClosed :: Stream -> IO Bool
isClosed Stream{..} = do
    tx <- readIORef $ sharedCloseSent streamShared
    rx <- readIORef $ sharedCloseReceived streamShared
    return (tx || rx)

----------------------------------------------------------------

is1RTTReady :: Stream -> IO Bool
is1RTTReady Stream{..} = readIORef $ shared1RTTReady streamShared

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
