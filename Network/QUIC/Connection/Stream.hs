{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Stream (
    getMyStreamId,
    possibleMyStreams,
    waitMyNewStreamId,
    waitMyNewUniStreamId,
    setTxMaxStreams,
    setTxUniMaxStreams,
    checkRxMaxStreams,
    updatePeerStreamId,
    checkStreamIdRoom,
) where

import Control.Concurrent.STM
import qualified Control.Exception as E

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Types

getMyStreamId :: Connection -> IO Int
getMyStreamId Connection{..} = do
    next <- currentStream <$> readTVarIO myStreamId
    return $ next - 4

possibleMyStreams :: Connection -> IO Int
possibleMyStreams Connection{..} = do
    Concurrency{..} <- readTVarIO myStreamId
    let StreamIdBase base = maxStreams
    return (base - (currentStream !>>. 2))

waitMyNewStreamId :: Connection -> IO StreamId
waitMyNewStreamId Connection{..} = get myStreamId

waitMyNewUniStreamId :: Connection -> IO StreamId
waitMyNewUniStreamId Connection{..} = get myUniStreamId

get :: TVar Concurrency -> IO Int
get tvar = atomically $ do
    conc@Concurrency{..} <- readTVar tvar
    let streamType = currentStream .&. 0b11
        StreamIdBase base = maxStreams
    check (currentStream < base * 4 + streamType)
    let currentStream' = currentStream + 4
    writeTVar tvar conc{currentStream = currentStream'}
    return currentStream

-- From "Peer", but set it to "My".
-- So, using "Tx".
setTxMaxStreams :: Connection -> Int -> IO ()
setTxMaxStreams Connection{..} = set myStreamId

setTxUniMaxStreams :: Connection -> Int -> IO ()
setTxUniMaxStreams Connection{..} = set myUniStreamId

-- | Raising the limit on the streams I may open.
--
-- A MAX_STREAMS that does not raise it is ignored (RFC 9000, section 4.6).
-- One of them reordered on the way, or retransmitted after a newer one has
-- gone out, would otherwise lower the limit.  'setTxMaxData' and
-- 'setTxMaxStreamData' guard the limits on data the same way.
set :: TVar Concurrency -> Int -> IO ()
set tvar mx = atomically $ modifyTVar' tvar raise
  where
    raise conc@Concurrency{..}
        | fromStreamIdBase maxStreams < mx = conc{maxStreams = StreamIdBase mx}
        | otherwise = conc

updatePeerStreamId :: Connection -> StreamId -> IO ()
updatePeerStreamId conn sid = do
    when
        ( (isClient conn && isServerInitiatedBidirectional sid)
            || (isServer conn && isClientInitiatedBidirectional sid)
        )
        $ do
            atomicModifyIORef'' (peerStreamId conn) checkConc
    when
        ( (isClient conn && isServerInitiatedUnidirectional sid)
            || (isServer conn && isClientInitiatedUnidirectional sid)
        )
        $ do
            atomicModifyIORef'' (peerUniStreamId conn) checkConc
  where
    checkConc conc@Concurrency{..}
        | currentStream < sid = conc{currentStream = sid}
        | otherwise = conc

checkRxMaxStreams :: Connection -> StreamId -> IO Bool
checkRxMaxStreams conn@Connection{..} sid = do
    Concurrency{..} <- if isClient conn then readForClient else readForServer
    let StreamIdBase base = maxStreams
        ok = sid < base * 4 + streamType
    return ok
  where
    streamType = sid .&. 0b11
    readForClient = case streamType of
        0 -> readTVarIO myStreamId
        1 -> readIORef peerStreamId
        2 -> readTVarIO myUniStreamId
        3 -> readIORef peerUniStreamId
        _ -> E.throwIO MustNotReached
    readForServer = case streamType of
        0 -> readIORef peerStreamId
        1 -> readTVarIO myStreamId
        2 -> readIORef peerUniStreamId
        3 -> readTVarIO myUniStreamId
        _ -> E.throwIO MustNotReached

-- | Counting one of the peer's streams as done with, and answering the new
--   limit for MAX_STREAMS if it is time to announce one.
--
-- The limit is the initial one plus the number of the peer's streams we are
-- done with, so that no more than the initial number are open at once
-- (RFC 9000, section 4.6).  It is announced once it has gone up by half the
-- initial number, rather than for every stream.
--
-- It used to be the highest stream the peer had opened plus the initial
-- number, whenever a stream was closed and the peer was close to its limit.
-- A peer keeping its streams open was then given a whole new window every
-- time we closed one of them, and could keep any number open: one closing a
-- tenth of what it opened held over three thousand open within seconds,
-- against a limit of 64.  The initial number was taken from the limit for
-- bidirectional streams for unidirectional ones too.
checkStreamIdRoom :: Connection -> Direction -> IO (Maybe Int)
checkStreamIdRoom conn dir = do
    let ref
            | dir == Bidirectional = peerStreamId conn
            | otherwise = peerUniStreamId conn
    atomicModifyIORef' ref checkConc
  where
    params = getMyParameters conn
    initialStreams
        | dir == Bidirectional = initialMaxStreamsBidi params
        | otherwise = initialMaxStreamsUni params
    checkConc conc@Concurrency{..} =
        let StreamIdBase base = maxStreams
            closed = closedStreams + 1
            base' = initialStreams + closed
            conc' = conc{closedStreams = closed}
         in if base' - base >= max 1 (initialStreams `div` 2)
                then (conc'{maxStreams = StreamIdBase base'}, Just base')
                else (conc', Nothing)
