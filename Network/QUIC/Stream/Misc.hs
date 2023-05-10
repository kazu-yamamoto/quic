{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Misc (
    getTxStreamOffset
  , isTxStreamClosed
  , setTxStreamClosed
  , getRxStreamOffset
  , isRxStreamClosed
  , setRxStreamClosed
  --
  , readStreamFlowTx
  , addTxStreamData
  , setTxMaxStreamData
  , readStreamFlowRx
  , addRxStreamData
  , setRxMaxStreamData
  , addRxMaxStreamData
  , getRxMaxStreamData
  , getRxStreamWindow
  ) where

import UnliftIO.STM

import Network.QUIC.Imports
import Network.QUIC.Stream.Queue
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

setTxStreamClosed :: Stream -> IO ()
setTxStreamClosed Stream{..} = atomicModifyIORef'' streamStateTx set
  where
    set (StreamState off _) = StreamState off True

----------------------------------------------------------------

getRxStreamOffset :: Stream -> Int -> IO Offset
getRxStreamOffset Stream{..} len = atomicModifyIORef' streamStateRx get
  where
    get (StreamState off fin) = (StreamState (off + len) fin, off)

isRxStreamClosed :: Stream -> IO Bool
isRxStreamClosed Stream{..} = do
    StreamState _ fin <- readIORef streamStateRx
    return fin

setRxStreamClosed :: Stream -> IO ()
setRxStreamClosed strm@Stream{..} = do
    atomicModifyIORef'' streamStateRx set
    putRecvStreamQ strm ""
  where
    set (StreamState off _) = StreamState off True

----------------------------------------------------------------

readStreamFlowTx :: Stream -> STM Flow
readStreamFlowTx Stream{..} = readTVar streamFlowTx

----------------------------------------------------------------

addTxStreamData :: Stream -> Int -> STM ()
addTxStreamData Stream{..} n = modifyTVar' streamFlowTx add
  where
    add flow = flow { flowData = flowData flow + n }

setTxMaxStreamData :: Stream -> Int -> IO ()
setTxMaxStreamData Stream{..} n = atomically $ modifyTVar' streamFlowTx set
  where
    set flow
     | flowMaxData flow < n = flow { flowMaxData = n }
     | otherwise            = flow

----------------------------------------------------------------

addRxStreamData :: Stream -> Int -> IO ()
addRxStreamData Stream{..} n = atomicModifyIORef'' streamFlowRx add
  where
    add flow = flow { flowData = flowData flow + n }

setRxMaxStreamData :: Stream -> Int -> IO ()
setRxMaxStreamData Stream{..} n = atomicModifyIORef'' streamFlowRx
    $ \flow -> flow { flowMaxData = n }

addRxMaxStreamData :: Stream -> Int -> IO Int
addRxMaxStreamData Stream{..} n = atomicModifyIORef' streamFlowRx add
  where
    add flow = (flow { flowMaxData = m }, m)
      where
        m = flowMaxData flow + n

getRxMaxStreamData :: Stream -> IO Int
getRxMaxStreamData Stream{..} = flowMaxData <$> readIORef streamFlowRx

getRxStreamWindow :: Stream -> IO Int
getRxStreamWindow Stream{..} = flowWindow <$> readIORef streamFlowRx

readStreamFlowRx :: Stream -> IO Flow
readStreamFlowRx Stream{..} = readIORef streamFlowRx
