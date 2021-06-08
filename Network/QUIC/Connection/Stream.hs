{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Stream (
    getMyStreamId
  , waitMyNewStreamId
  , waitMyNewUniStreamId
  , setMyMaxStreams
  , setMyUniMaxStreams
  , getPeerMaxStreams
  , setPeerMaxStreams
  ) where

import Control.Concurrent.STM

import Network.QUIC.Connection.Types
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
    check (currentStream < maxStreams * 4 + streamType)
    let currentStream' = currentStream + 4
    writeTVar tvar conc { currentStream = currentStream' }
    return currentStream

setMyMaxStreams :: Connection -> Int -> IO ()
setMyMaxStreams Connection{..} = set myStreamId

setMyUniMaxStreams :: Connection -> Int -> IO ()
setMyUniMaxStreams Connection{..} = set myUniStreamId

set :: TVar Concurrency -> Int -> IO ()
set tvar mx = atomically $ modifyTVar tvar $ \c -> c { maxStreams = mx }

setPeerMaxStreams :: Connection -> Int -> IO ()
setPeerMaxStreams Connection{..} n =
    atomicModifyIORef'' peerStreamId $ \c -> c { maxStreams = n }

getPeerMaxStreams :: Connection -> IO Int
getPeerMaxStreams Connection{..} = atomicModifyIORef' peerStreamId inc
  where
    inc c = (c { maxStreams = next}, next)
      where
        next = maxStreams c + 1
