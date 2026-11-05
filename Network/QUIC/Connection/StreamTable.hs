{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    createStream,
    claimPeerStream,
    findStream,
    addStream,
    delStream,
    keepDepartedStream,
    noteDepartedRxFrame,
    initialRxMaxStreamData,
    setupCryptoStreams,
    clearCryptoStream,
    getCryptoStream,
) where

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
findStream Connection{..} sid = lookupStream sid <$> readIORef streamTable

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
    atomicModifyIORef'' streamTable $ insertStream sid strm
    return strm

delStream :: Connection -> Stream -> IO ()
delStream Connection{..} strm =
    atomicModifyIORef'' streamTable $ deleteStream $ streamId strm

----------------------------------------------------------------

-- | Keeping account of a stream the application has closed before the peer
--   finished it.
--
-- A frame that arrives for a stream no longer in the table is dropped, but
-- the peer spent its window on it all the same.  'Network.QUIC.IO.releaseStream'
-- gives back what had been seen by the time of the close; this is for what
-- arrives after it, and for holding it to the limits it was sent under.
--
-- Nothing is kept for a stream the peer has finished: its final size is
-- known and accounted for, and anything that still arrives for it lies
-- inside that.  Nor for one we only send on.  'True' if it is kept.
keepDepartedStream :: Connection -> Stream -> IO Bool
keepDepartedStream conn strm
    | sendOnly = return False
    | otherwise = do
        RxBounds{..} <- getRxBounds strm
        case rxFinal of
            Just _ -> return False
            Nothing -> do
                lim <- getRxMaxStreamData strm
                atomicModifyIORef'' (departedStreams conn) $
                    IntMap.insert sid $
                        Departed rxHighest lim
                return True
  where
    sid = streamId strm
    sendOnly
        | isClient conn = isClientInitiatedUnidirectional sid
        | otherwise = isServerInitiatedUnidirectional sid

-- | Noting a frame that arrived for a stream the application has closed.
--
-- Answered, as for a live stream, with how far it takes the stream past what
-- has been seen of it, which the connection counts as received and, since
-- nobody will read it, as consumed too; and with whether the stream has now
-- ended and is forgotten.  A copy of what was seen moves nothing.  Nothing
-- when the stream is not kept, and a transport error for a frame the stream
-- would have refused.
noteDepartedRxFrame
    :: Connection
    -> StreamId
    -> Int
    -> Bool
    -> IO (Either (TransportError, ReasonPhrase) (Int, Bool))
noteDepartedRxFrame Connection{..} sid end fin =
    atomicModifyIORef' departedStreams note
  where
    note tbl = case IntMap.lookup sid tbl of
        Nothing -> (tbl, Right (0, False))
        Just d@Departed{..}
            -- FLOW CONTROL: MAX_STREAM_DATA: recv: rejecting if over my limit
            | end > depLimit ->
                (tbl, Left (FlowControlError, "Flow control error for a closed stream"))
            -- RFC 9000 Sec 4.5: "even after a stream is closed".
            | fin && end < depHighest ->
                (tbl, Left (FinalSizeError, "a final size below what the stream has reached"))
            | fin -> (IntMap.delete sid tbl, Right (end - depHighest, True))
            | otherwise ->
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
    stbl0 <- readIORef streamTable
    stbl <- insertCryptoStreams conn stbl0
    writeIORef streamTable stbl

clearCryptoStream :: Connection -> EncryptionLevel -> IO ()
clearCryptoStream Connection{..} lvl =
    atomicModifyIORef'' streamTable $ deleteCryptoStream lvl

----------------------------------------------------------------

getCryptoStream :: Connection -> EncryptionLevel -> IO (Maybe Stream)
getCryptoStream Connection{..} lvl =
    lookupCryptoStream lvl <$> readIORef streamTable
