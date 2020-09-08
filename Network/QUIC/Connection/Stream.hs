{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Stream (
    getMyNewStreamId
  , getMyNewUniStreamId
  , setMyMaxStreams
  , setMyUniMaxStreams
  , getPeerMaxStreams
  , setPeerMaxStreams
  ) where

import Control.Concurrent.STM

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

getMyNewStreamId :: Connection -> IO StreamId
getMyNewStreamId Connection{..} = get myStreamId

getMyNewUniStreamId :: Connection -> IO StreamId
getMyNewUniStreamId Connection{..} = get myUniStreamId

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
getPeerMaxStreams Connection{..} =
    atomicModifyIORef' peerStreamId $ \c -> (c { maxStreams = maxStreams c + 1}, maxStreams c)
