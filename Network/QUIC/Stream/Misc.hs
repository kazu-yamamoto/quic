{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Misc (
    getTxStreamOffset,
    isTxStreamClosed,
    setTxStreamClosed,
    getRxStreamOffset,
    isRxStreamClosed,
    setRxStreamClosed,
    --
    readStreamFlowTx,
    addTxStreamData,
    setTxMaxStreamData,
    --
    getRxMaxStreamData,
    addRxStreamData,
    updateStreamFlowRx,
) where

import Network.Control
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
    -- Sending a pseudo FIN so that recvStream doesn't block.
    -- See https://github.com/kazu-yamamoto/quic/pull/54
    putRecvStreamQ strm ""
  where
    set (StreamState off _) = StreamState off True

----------------------------------------------------------------

readStreamFlowTx :: Stream -> STM TxFlow
readStreamFlowTx Stream{..} = readTVar streamFlowTx

----------------------------------------------------------------

addTxStreamData :: Stream -> Int -> STM ()
addTxStreamData Stream{..} n = modifyTVar' streamFlowTx add
  where
    add flow = flow{txfSent = txfSent flow + n}

setTxMaxStreamData :: Stream -> Int -> IO ()
setTxMaxStreamData Stream{..} n = atomically $ modifyTVar' streamFlowTx set
  where
    set flow
        | txfLimit flow < n = flow{txfLimit = n}
        | otherwise = flow

----------------------------------------------------------------

getRxMaxStreamData :: Stream -> IO Int
getRxMaxStreamData Stream{..} = rxfLimit <$> readIORef streamFlowRx

addRxStreamData :: Stream -> Int -> IO ()
addRxStreamData Stream{..} n = atomicModifyIORef'' streamFlowRx add
  where
    add flow = flow{rxfReceived = rxfReceived flow + n}

updateStreamFlowRx :: Stream -> Int -> IO (Maybe Int)
updateStreamFlowRx Stream{..} consumed =
    atomicModifyIORef' streamFlowRx $ maybeOpenRxWindow consumed FCTMaxData

{- cannot be used due to reassemble.
checkRxMaxStreamData :: Stream -> Int -> IO Bool
checkRxMaxStreamData Stream{..} len =
    atomicModifyIORef' streamFlowRx $ checkRxLimit len
-}
