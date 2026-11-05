{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Misc (
    resetTxStream,
    isTxStreamReset,
    getTxStreamOffset,
    isTxStreamClosed,
    setTxStreamClosed,
    getRxStreamOffset,
    isRxStreamClosed,
    setRxStreamClosed,
    resetReceived,
    setResetReceived,
    markReleased,
    FinalSizeProblem (..),
    getRxBounds,
    noteRxFrame,
    noteRxFinalSize,
    addRxCredited,
    takeRxOwed,
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

-- | Reset the sending part and return its final size: every octet handed
--   to the sender, sent or still queued.  The sender drops what is queued,
--   so nothing goes out past it.
resetTxStream :: Stream -> IO Offset
resetTxStream s@Stream{..} = do
    -- Before the read: what is queued after it is dropped, not counted.
    atomicWriteIORef streamResetTx True
    setTxStreamClosed s
    txfSent <$> readTVarIO streamFlowTx

isTxStreamReset :: Stream -> IO Bool
isTxStreamReset Stream{..} = readIORef streamResetTx

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

----------------------------------------------------------------

-- | What is wrong with where a peer says its stream ends.
--
-- RFC 9000 Sec 4.5: "Once a final size for a stream is known, it cannot
-- change.  If a RESET_STREAM or STREAM frame is received indicating a change
-- in the final size for the stream, an endpoint SHOULD respond with an error
-- of type FINAL_SIZE_ERROR. ... A receiver SHOULD treat receipt of data at or
-- beyond the final size as an error of type FINAL_SIZE_ERROR, even after a
-- stream is closed."
data FinalSizeProblem
    = -- | A final size that is not the one already known
      FinalSizeChanged
    | -- | A final size below what has already been seen of the stream
      FinalSizeTooSmall
    | -- | Data at or beyond a final size already known
      DataPastFinalSize
    deriving (Eq, Show)

-- | What the receiving side has seen of where this stream ends.
getRxBounds :: Stream -> IO RxBounds
getRxBounds Stream{..} = readIORef streamRxBounds

-- | Answering with how far the frame takes the stream past what has been
--   seen of it: what the connection's flow controller is to count as
--   received for it (RFC 9000 Sec 4.1).  A copy of what was seen is 0.
noteRxFrame :: Stream -> Int -> Bool -> IO (Either FinalSizeProblem Int)
noteRxFrame Stream{..} end fin = atomicModifyIORef' streamRxBounds note
  where
    note b@RxBounds{..}
        | fin = case rxFinal of
            Just f
                | f /= end -> (b, Left FinalSizeChanged)
            _
                | end < rxHighest -> (b, Left FinalSizeTooSmall)
                | otherwise -> (b{rxFinal = Just end, rxHighest = end}, Right (end - rxHighest))
        | otherwise = case rxFinal of
            Just f
                | end > f -> (b, Left DataPastFinalSize)
            _ -> (b{rxHighest = max rxHighest end}, Right (max 0 (end - rxHighest)))

-- | The same for the final size a RESET_STREAM carries.
noteRxFinalSize :: Stream -> Int -> IO (Either FinalSizeProblem Int)
noteRxFinalSize s end = noteRxFrame s end True

-- | Counting octets as consumed on the stream's behalf though the
--   application has not read them.
addRxCredited :: Stream -> Int -> IO ()
addRxCredited Stream{..} n =
    atomicModifyIORef'' streamRxBounds $ \b -> b{rxCredited = rxCredited b + n}

-- | What the connection's flow controller has counted as received for the
--   stream and nobody has counted as consumed: what is owed back once the
--   application is done with it.
--
-- What it read it has already counted itself, in 'recvStream'.  The rest --
-- a request body a server answers without reading, or what was lost on the
-- way of a stream whose end is known -- was spent by the peer all the same,
-- and left uncounted the window we advertise stays that much smaller for
-- the rest of the connection.
--
-- Answered once for each octet: what is answered here is counted as
-- credited.
takeRxOwed :: Stream -> IO Int
takeRxOwed Stream{..} = do
    consumed <- rxfConsumed <$> readIORef streamFlowRx
    atomicModifyIORef' streamRxBounds $ take' consumed
  where
    take' consumed b@RxBounds{..}
        | owed > 0 = (b{rxCredited = rxCredited + owed}, owed)
        | otherwise = (b, 0)
      where
        owed = rxHighest - consumed - rxCredited
