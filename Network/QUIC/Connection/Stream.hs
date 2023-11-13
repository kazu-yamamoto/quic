{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Stream (
    getMyStreamId
  , waitMyNewStreamId
  , waitMyNewUniStreamId
  , setTxMaxStreams
  , setTxUniMaxStreams
  , readRxMaxStreams
  , checkStreamIdRoom
  ) where

import UnliftIO.STM

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Types
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
    writeTVar tvar conc { currentStream = currentStream' }
    return currentStream

-- From "Peer", but set it to "My".
-- So, using "Tx".
setTxMaxStreams :: Connection -> Int -> IO ()
setTxMaxStreams Connection{..} = set myStreamId

setTxUniMaxStreams :: Connection -> Int -> IO ()
setTxUniMaxStreams Connection{..} = set myUniStreamId

set :: TVar Concurrency -> Int -> IO ()
set tvar mx = atomically $ modifyTVar tvar $ \c -> c { maxStreams = StreamIdBase mx }

readRxMaxStreams :: Connection -> StreamId -> IO Int
readRxMaxStreams Connection{..} sid = do
    Concurrency{..} <- readIORef peerStreamId
    let StreamIdBase base = maxStreams
    return $ base * 4 + streamType
  where
    streamType = sid .&. 0b11

checkStreamIdRoom :: Connection -> Direction -> IO (Maybe Int)
checkStreamIdRoom conn dir = do
    let ref | dir == Bidirectional = peerStreamId conn
            | otherwise            = peerUniStreamId conn
    atomicModifyIORef' ref check
  where
    check conc@Concurrency{..} =
        let StreamIdBase base = maxStreams
            initialStreams = initialMaxStreamsBidi $ getMyParameters conn
            cbase = currentStream !>>. 2
        in if (base - cbase < (initialStreams !>>. 1)) then
           (conc, Nothing)
          else
           let base' = base + initialStreams
           in (conc { maxStreams = StreamIdBase base' }, Just base')
