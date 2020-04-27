{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Stream (
    getMyNewStreamId
  , getMyNewUniStreamId
  , getPeerStreamID
  , setPeerStreamID
  , getStreamFin
  , setStreamFin
  ) where

import Data.IORef

import Network.QUIC.Connection.Types
import Network.QUIC.Types

getMyNewStreamId :: Connection -> IO StreamId
getMyNewStreamId conn = atomicModifyIORef' (myStreamId conn) inc4

getMyNewUniStreamId :: Connection -> IO StreamId
getMyNewUniStreamId conn = atomicModifyIORef' (myUniStreamId conn) inc4

inc4 :: StreamId -> (StreamId,StreamId)
inc4 n = let n' = n + 4 in (n', n)

getPeerStreamID :: Connection -> IO StreamId
getPeerStreamID conn = readIORef $ peerStreamId conn

setPeerStreamID :: Connection -> StreamId -> IO ()
setPeerStreamID conn sid =  writeIORef (peerStreamId conn) sid

getStreamFin :: Stream -> IO Fin
getStreamFin Stream{..} = do
    StreamState _ fin <- readIORef streamStateTx
    return fin

setStreamFin :: Stream -> IO ()
setStreamFin Stream{..} = do
    StreamState off _ <- readIORef streamStateTx
    writeIORef streamStateTx $ StreamState off True

