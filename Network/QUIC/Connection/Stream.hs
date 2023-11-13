{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Stream (
    getMyStreamId
  , waitMyNewStreamId
  , waitMyNewUniStreamId
  , setTxMaxStreams
  , setTxUniMaxStreams
  , readRxMaxStreams
  , getRxMaxStreams
  , getRxMaxUniStreams
  , addRxMaxStreams
  , addRxMaxUniStreams
  , getRxCurrentStream
  , getRxCurrentUniStream
  ) where

import UnliftIO.STM

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

readRxMaxStreams :: Connection -> StreamId -> IO Int
readRxMaxStreams Connection{..} sid = do
    n <- maxStreams <$> readIORef peerStreamId
    return $ n * 4 + iniType
  where
    iniType = sid .&. 0x3

getRxMaxStreams :: Connection -> IO Int
getRxMaxStreams Connection{..} = maxStreams <$> readIORef peerStreamId

getRxMaxUniStreams :: Connection -> IO Int
getRxMaxUniStreams Connection{..} = maxStreams <$> readIORef peerUniStreamId

addRxMaxStreams :: Connection -> Int -> IO Int
addRxMaxStreams Connection{..} n =
    atomicModifyIORef' peerStreamId $ \c ->
       let max' = maxStreams c + n
       in (c { maxStreams = max' }, max')

addRxMaxUniStreams :: Connection -> Int -> IO Int
addRxMaxUniStreams Connection{..} n =
    atomicModifyIORef' peerUniStreamId $ \c ->
       let max' = maxStreams c + n
       in (c { maxStreams = max' }, max')

getRxCurrentStream :: Connection -> IO Int
getRxCurrentStream Connection{..} = currentStream <$> readIORef peerStreamId

getRxCurrentUniStream :: Connection -> IO Int
getRxCurrentUniStream Connection{..} = currentStream <$> readIORef peerUniStreamId
