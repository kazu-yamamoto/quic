{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Misc (
    getTxStreamFinalSize,
    getTxStreamOffset,
    isTxStreamClosed,
    setTxStreamClosed,
    getRxStreamOffset,
    isRxStreamClosed,
    setRxStreamClosed,
    resetReceived,
    setResetReceived,
    markReleased,
    --
    readStreamFlowTx,
    addTxStreamData,
    setTxMaxStreamData,
    --
    getRxMaxStreamData,
    addRxStreamData,
    updateStreamFlowRx,
) where

import Control.Concurrent.STM
import Network.Control

import Network.QUIC.Imports
import Network.QUIC.Stream.Queue
import Network.QUIC.Stream.Types
import Network.QUIC.Types (ApplicationProtocolError)

----------------------------------------------------------------

getTxStreamFinalSize :: Stream -> IO Offset
getTxStreamFinalSize Stream{..} = streamOffset <$> readIORef streamStateTx

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

-- | The error code of the RESET_STREAM the peer sent for this stream, if it
--   sent one.
--
-- After a RESET_STREAM, 'recvStream' returns an empty 'ByteString', just as
-- it does at the end of the stream.  This tells the two apart: HTTP/3, for
-- one, has to tell its QPACK encoder about a request whose reset it saw
-- (RFC 9204, section 4.4.2), and had no way to know that it was reset.
resetReceived :: Stream -> IO (Maybe ApplicationProtocolError)
resetReceived Stream{..} = readIORef streamResetRx

setResetReceived :: Stream -> ApplicationProtocolError -> IO ()
setResetReceived Stream{..} aerr = writeIORef streamResetRx $ Just aerr

-- | Marking the stream as done with; 'True' only the first time.
markReleased :: Stream -> IO Bool
markReleased Stream{..} = atomicModifyIORef' streamReleased $ \done -> (True, not done)

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
