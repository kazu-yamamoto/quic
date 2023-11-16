{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Stream (
    getMyStreamId,
    waitMyNewStreamId,
    waitMyNewUniStreamId,
    setTxMaxStreams,
    setTxUniMaxStreams,
    checkRxMaxStreams,
    updatePeerStreamId,
    checkStreamIdRoom,
) where

import UnliftIO.STM

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

waitMyNewStreamId :: Connection -> IO StreamId
waitMyNewStreamId Connection{..} = get myStreamId

waitMyNewUniStreamId :: Connection -> IO StreamId
waitMyNewUniStreamId Connection{..} = get myUniStreamId

get :: TVar Concurrency -> IO Int
get tvar = atomically $ do
    conc@Concurrency{..} <- readTVar tvar
    let streamType = currentStream .&. 0b11
        StreamIdBase base = maxStreams
    checkSTM (currentStream < base * 4 + streamType)
    let currentStream' = currentStream + 4
    writeTVar tvar conc{currentStream = currentStream'}
    return currentStream

-- From "Peer", but set it to "My".
-- So, using "Tx".
setTxMaxStreams :: Connection -> Int -> IO ()
setTxMaxStreams Connection{..} = set myStreamId

setTxUniMaxStreams :: Connection -> Int -> IO ()
setTxUniMaxStreams Connection{..} = set myUniStreamId

set :: TVar Concurrency -> Int -> IO ()
set tvar mx = atomically $ modifyTVar tvar $ \c -> c{maxStreams = StreamIdBase mx}

updatePeerStreamId :: Connection -> StreamId -> IO ()
updatePeerStreamId conn sid = do
    when
        ( (isClient conn && isServerInitiatedBidirectional sid)
            || (isServer conn && isClientInitiatedBidirectional sid)
        )
        $ do
            atomicModifyIORef'' (peerStreamId conn) check
    when
        ( (isClient conn && isServerInitiatedUnidirectional sid)
            || (isServer conn && isClientInitiatedUnidirectional sid)
        )
        $ do
            atomicModifyIORef'' (peerUniStreamId conn) check
  where
    check conc@Concurrency{..}
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
        _ -> error "never reach"
    readForServer = case streamType of
        0 -> readIORef peerStreamId
        1 -> readTVarIO myStreamId
        2 -> readIORef peerUniStreamId
        3 -> readTVarIO myUniStreamId
        _ -> error "never reach"

checkStreamIdRoom :: Connection -> Direction -> IO (Maybe Int)
checkStreamIdRoom conn dir = do
    let ref
            | dir == Bidirectional = peerStreamId conn
            | otherwise = peerUniStreamId conn
    atomicModifyIORef' ref check
  where
    check conc@Concurrency{..} =
        let StreamIdBase base = maxStreams
            initialStreams = initialMaxStreamsBidi $ getMyParameters conn
            cbase = currentStream !>>. 2
         in if (base - cbase < (initialStreams !>>. 3))
                then
                    let base' = cbase + initialStreams
                     in (conc{maxStreams = StreamIdBase base'}, Just base')
                else (conc, Nothing)
