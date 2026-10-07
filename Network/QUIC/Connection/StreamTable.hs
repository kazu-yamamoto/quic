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
-- A frame that arrives for a stream no longer in the table is dropped, and
-- what the peer spent on it is then counted by nobody: not as received,
-- since we never looked at it, and not as consumed, since nobody will read
-- it.  The window we advertise falls that much behind what the peer
-- believes it has spent, for the rest of the connection, and a server that
-- answers requests without reading their bodies runs its peers out of
-- window.  'Network.QUIC.IO.releaseStream' gives back what had arrived by
-- the time of the close; this is for what arrives after it.
--
-- Nothing is kept for a stream the peer has finished: its final size is
-- known and accounted for, and anything that still arrives for it lies
-- inside that and has been counted already.
keepDepartedStream :: Connection -> Stream -> IO ()
keepDepartedStream Connection{..} strm = do
    b <- getRxBounds strm
    unless (settled b) $
        atomicModifyIORef'' departedStreams $
            IntMap.insert (streamId strm) b

-- | Is there nothing more this stream can owe?
settled :: RxBounds -> Bool
settled RxBounds{..} = rxFinal == Just rxCounted

-- | Noting a frame that arrived for a stream the application has closed,
--   and answering with what the connection's window is owed for it.
--
-- The peer's own flow control counts the offsets it has sent, not the
-- octets that reached us, so what is owed is measured the same way: the
-- furthest point of the stream anything has reached, less what has been
-- accounted for already.  A retransmission does not move that point and so
-- is owed nothing, which is what keeps this from counting twice -- the
-- reassembly that tells a copy from new data went with the stream.
noteDepartedRxFrame :: Connection -> StreamId -> Int -> Bool -> IO Int
noteDepartedRxFrame Connection{..} sid end fin =
    atomicModifyIORef' departedStreams note
  where
    note tbl = case IntMap.lookup sid tbl of
        Nothing -> (tbl, 0)
        Just b ->
            let b' = account b
             in ( if settled b' then IntMap.delete sid tbl else IntMap.insert sid b' tbl
                , rxCounted b' - rxCounted b
                )
    account b@RxBounds{..} =
        b
            { rxCounted = reached
            , rxHighest = max rxHighest end
            , rxFinal = if fin then Just end else rxFinal
            }
      where
        -- Never past the end the peer has said the stream has: a frame
        -- claiming to reach beyond it is for the live path to refuse, and
        -- this one is not the place to answer it.
        reached = case (if fin then Just end else rxFinal) of
            Just f -> min f $ max rxCounted end
            Nothing -> max rxCounted end

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
