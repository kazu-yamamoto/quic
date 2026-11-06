{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    createStream,
    claimPeerStream,
    findStream,
    addStream,
    resetTxStreamLimits,
    delStream,
    departStream,
    Arrival (..),
    noteRxArrival,
    initialRxMaxStreamData,
    setupCryptoStreams,
    clearCryptoStream,
    getCryptoStream,
) where

import Control.Concurrent.STM
import qualified Data.IntMap.Strict as IntMap
import qualified Data.IntSet as IntSet

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Stream
import Network.QUIC.Types

createStream :: Connection -> StreamId -> IO Stream
createStream conn sid = do
    strm <- addStream conn sid
    putInput conn $ InpStream strm
    return strm

-- | Recording that a peer-initiated stream is opened.  'False' if it was
--   opened before, which, for one no longer in the stream table, means that it
--   has been closed.
--
-- The skipped ids never outnumber the streams we allow the peer, as a frame
-- for a stream past that limit is refused before it gets here.
claimPeerStream :: Connection -> StreamId -> IO Bool
claimPeerStream conn sid = atomicModifyIORef' ref claim
  where
    ref
        | isUnidirectional sid = peerUniOpened conn
        | otherwise = peerOpened conn
    claim os@OpenedStreams{..}
        | sid >= openedNext =
            let skipped = IntSet.fromDistinctAscList [openedNext, openedNext + 4 .. sid - 4]
             in (OpenedStreams (sid + 4) (openedSkipped <> skipped), True)
        | sid `IntSet.member` openedSkipped =
            (os{openedSkipped = IntSet.delete sid openedSkipped}, True)
        | otherwise = (os, False)

findStream :: Connection -> StreamId -> IO (Maybe Stream)
findStream Connection{..} sid = lookupStream sid <$> readTVarIO streamTable

addStream :: Connection -> StreamId -> IO Stream
addStream conn@Connection{..} sid = do
    strm <-
        if isClient conn
            then do
                serverParams <- getPeerParameters conn
                let txLim = serverInitial sid serverParams
                let clientParams = getMyParameters conn
                    rxLim = clientInitial sid clientParams
                newStream conn sid txLim rxLim
            else do
                clientParams <- getPeerParameters conn
                let txLim = clientInitial sid clientParams
                    serverParams = getMyParameters conn
                    rxLim = serverInitial sid serverParams
                newStream conn sid txLim rxLim
    atomically $ modifyTVar' streamTable $ insertStream sid strm
    return strm

-- | 0-RTT rejected (RFC 9001 Sec 4.6.2): the streams the client opened
--   under the remembered limits are held to what the server gives now.
resetTxStreamLimits :: Connection -> Parameters -> IO ()
resetTxStreamLimits Connection{..} serverParams = do
    strms <- tableStreams <$> readTVarIO streamTable
    forM_ strms $ \strm -> do
        let sid = streamId strm
        when (sid >= 0 && isClientInitiated sid) $
            resetTxMaxStreamData strm $
                serverInitial sid serverParams

delStream :: Connection -> Stream -> IO ()
delStream Connection{..} strm =
    atomically $ modifyTVar' streamTable $ deleteStream $ streamId strm

----------------------------------------------------------------

-- | Taking a stream the application is done with out of the table, and
--   answering with what its window is owed back and whether anything is
--   kept of it.
--
-- A frame that arrives for a stream no longer in the table is dropped, but
-- the peer spent its window on it all the same.  What has been seen by now
-- is owed back here; what arrives after is owed by what is kept, which also
-- holds it to the limits it was sent under.  Nothing is kept for a stream
-- the peer has finished, its final size known and accounted for, nor for
-- one we only send on.
--
-- One transaction, and 'noteRxArrival' another, so that a frame is seen
-- either before the stream leaves the table, and counted in what is owed
-- here, or after, and counted in what is kept.  Done in steps, a frame
-- arriving in between was counted in neither, and a FIN lost that way left
-- the stream kept for good.
departStream :: Connection -> Stream -> IO (Int, Bool)
departStream conn strm = do
    -- The application's own, which only it moves.
    consumed <- getRxConsumed strm
    lim <- getRxMaxStreamData strm
    atomically $ do
        modifyTVar' (streamTable conn) $ deleteStream sid
        owed <- takeRxOwedSTM strm consumed
        RxBounds{..} <- getRxBoundsSTM strm
        let kept = not sendOnly && isNothing rxFinal
        when kept $
            modifyTVar' (departedStreams conn) $
                IntMap.insert sid $
                    Departed rxHighest lim
        return (owed, kept)
  where
    sid = streamId strm
    sendOnly
        | isClient conn = isClientInitiatedUnidirectional sid
        | otherwise = isServerInitiatedUnidirectional sid

-- | Where a STREAM or RESET_STREAM frame lands, with what it counts there.
data Arrival
    = -- | A stream in the table, with how far the frame takes it
      ArrivedLive Stream (Either FinalSizeProblem Int)
    | -- | A stream the application has closed and the peer has not finished:
      --   how far the frame takes it and whether it has ended now, or the
      --   transport error the stream would have refused it with
      ArrivedDeparted (Either (TransportError, ReasonPhrase) (Int, Bool))
    | -- | Neither: a stream to open, or one closed and done with
      ArrivedNowhere

-- | Finding the stream a frame reaching @end@ is for and noting the frame
--   there, as one transaction against 'departStream'.
--
-- For a stream the application has closed, as for a live one, what moves is
-- how far the frame takes it past what has been seen, which the connection
-- counts as received and, nobody being left to read it, as consumed too.
-- A copy of what was seen moves nothing.  @unread@ says nobody will read
-- what moves on a live stream either, the tail a RESET_STREAM gives up: it
-- is counted as credited here, or 'departStream' could credit it again.
noteRxArrival :: Connection -> StreamId -> Int -> Bool -> Bool -> IO Arrival
noteRxArrival Connection{..} sid end fin unread = atomically $ do
    found <- lookupStream sid <$> readTVar streamTable
    case found of
        Just strm -> do
            r <- noteRxFrameSTM strm end fin
            case r of
                Right n | unread -> addRxCreditedSTM strm n
                _ -> return ()
            return $ ArrivedLive strm r
        Nothing -> do
            tbl <- readTVar departedStreams
            case IntMap.lookup sid tbl of
                Nothing -> return ArrivedNowhere
                Just d -> do
                    let (tbl', r) = note tbl d
                    writeTVar departedStreams tbl'
                    return $ ArrivedDeparted r
  where
    note tbl d@Departed{..}
        -- FLOW CONTROL: MAX_STREAM_DATA: recv: rejecting if over my limit
        | end > depLimit =
            (tbl, Left (FlowControlError, "Flow control error for a closed stream"))
        -- RFC 9000 Sec 4.5: "even after a stream is closed".
        | fin && end < depHighest =
            (tbl, Left (FinalSizeError, "a final size below what the stream has reached"))
        | fin = (IntMap.delete sid tbl, Right (end - depHighest, True))
        | otherwise =
            ( IntMap.insert sid d{depHighest = max depHighest end} tbl
            , Right (max 0 (end - depHighest), False)
            )

initialRxMaxStreamData :: Connection -> StreamId -> Int
initialRxMaxStreamData conn sid
    | isClient conn = clientInitial sid params
    | otherwise = serverInitial sid params
  where
    params = getMyParameters conn

clientInitial :: StreamId -> Parameters -> Int
clientInitial sid params
    | isClientInitiatedBidirectional sid = initialMaxStreamDataBidiLocal params
    | isServerInitiatedBidirectional sid = initialMaxStreamDataBidiRemote params
    -- intentionally not using isServerInitiatedUnidirectional
    | otherwise = initialMaxStreamDataUni params

serverInitial :: StreamId -> Parameters -> Int
serverInitial sid params
    | isServerInitiatedBidirectional sid = initialMaxStreamDataBidiLocal params
    | isClientInitiatedBidirectional sid = initialMaxStreamDataBidiRemote params
    -- intentionally not using isClientInitiatedUnidirectional
    | otherwise = initialMaxStreamDataUni params

----------------------------------------------------------------

setupCryptoStreams :: Connection -> IO ()
setupCryptoStreams conn@Connection{..} = do
    stbl0 <- readTVarIO streamTable
    stbl <- insertCryptoStreams conn stbl0
    atomically $ writeTVar streamTable stbl

clearCryptoStream :: Connection -> EncryptionLevel -> IO ()
clearCryptoStream Connection{..} lvl =
    atomically $ modifyTVar' streamTable $ deleteCryptoStream lvl

----------------------------------------------------------------

getCryptoStream :: Connection -> EncryptionLevel -> IO (Maybe Stream)
getCryptoStream Connection{..} lvl =
    lookupCryptoStream lvl <$> readTVarIO streamTable
