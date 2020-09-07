{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Connection.Stream (
    getMyNewStreamId
  , getMyNewUniStreamId
  ) where

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

getMyNewStreamId :: Connection -> IO StreamId
getMyNewStreamId conn = atomicModifyIORef' (myStreamId conn) inc4

getMyNewUniStreamId :: Connection -> IO StreamId
getMyNewUniStreamId conn = atomicModifyIORef' (myUniStreamId conn) inc4

inc4 :: StreamId -> (StreamId,StreamId)
inc4 n = let n' = n + 4 in (n', n)
