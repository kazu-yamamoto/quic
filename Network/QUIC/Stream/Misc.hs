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
    FinalSizeProblem (..),
    noteRxFrame,
    noteRxFinalSize,
    addRxCounted,
    takeRxUncounted,
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

-- | Taking in where one STREAM frame says the stream reaches, and whether it
--   ends it.  Nothing is counted here: a frame may still turn out to be a
--   duplicate, and only what is taken counts.
noteRxFrame :: Stream -> Int -> Bool -> IO (Maybe FinalSizeProblem)
noteRxFrame Stream{..} end fin = atomicModifyIORef' streamRxBounds note
  where
    note b@RxBounds{..}
        | fin = case rxFinal of
            Just f
                | f /= end -> (b, Just FinalSizeChanged)
            _
                | end < rxHighest -> (b, Just FinalSizeTooSmall)
                | otherwise ->
                    (b{rxFinal = Just end, rxHighest = max rxHighest end}, Nothing)
        | otherwise = case rxFinal of
            Just f
                | end > f -> (b, Just DataPastFinalSize)
            _ -> (b{rxHighest = max rxHighest end}, Nothing)

-- | The same for the final size a RESET_STREAM carries.
noteRxFinalSize :: Stream -> Int -> IO (Maybe FinalSizeProblem)
noteRxFinalSize s end = noteRxFrame s end True

-- | Counting octets the connection's flow controller has taken for the
--   stream.
addRxCounted :: Stream -> Int -> IO ()
addRxCounted Stream{..} n =
    atomicModifyIORef'' streamRxBounds $ \b -> b{rxCounted = rxCounted b + n}

-- | The octets the peer spent on the stream that will never arrive, and
--   which the connection's flow controller has therefore not counted.
--
-- RFC 9000 Sec 4.5: "A receiver SHOULD use the final size to account for all
-- bytes sent on the stream in its connection-level flow controller."  Left
-- uncounted, the window we advertise falls behind what the peer believes it
-- has spent, by the tail of every stream it resets, until it has none left.
--
-- Answered once: whatever is asked for here is counted from then on.
takeRxUncounted :: Stream -> IO Int
takeRxUncounted Stream{..} = atomicModifyIORef' streamRxBounds take'
  where
    take' b@RxBounds{..} = case rxFinal of
        Just f
            | f > rxCounted -> (b{rxCounted = f}, f - rxCounted)
        _ -> (b, 0)
