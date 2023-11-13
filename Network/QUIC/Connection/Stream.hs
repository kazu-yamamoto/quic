{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Stream (
    getMyStreamId
  , waitMyNewStreamId
  , waitMyNewUniStreamId
  , setTxMaxStreams
  , setTxUniMaxStreams
  , getRxMaxStreams
  , setRxMaxStreams
  , readRxMaxStreams
  ) where

import UnliftIO.STM

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
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
    checkSTM (currentStream < maxStreams * 4 + streamType)
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
set tvar mx = atomically $ modifyTVar tvar $ \c -> c { maxStreams = mx }

setRxMaxStreams :: Connection -> Int -> IO ()
setRxMaxStreams Connection{..} n =
    atomicModifyIORef'' peerStreamId $ \c -> c { maxStreams = n }

readRxMaxStreams :: Connection -> IO Int
readRxMaxStreams conn@Connection{..} = do
    n <- maxStreams <$> readIORef peerStreamId
    return $ n * 4 + iniType
  where
    iniType | isClient conn = 1 -- peer is server
            | otherwise     = 0

getRxMaxStreams :: Connection -> IO Int
getRxMaxStreams Connection{..} = atomicModifyIORef' peerStreamId inc
  where
    inc c = (c { maxStreams = next}, next)
      where
        next = maxStreams c + 1
