{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    putInputStream
  , putInputCrypto
  , insertStream
  , insertCryptoStreams
  , getCryptoOffset
  ) where

import Data.IORef
import qualified Data.IntMap.Strict as Map

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

putInputStream :: Connection -> StreamId -> Offset -> StreamData -> Fin -> IO ()
putInputStream conn sid off dat fin = do
    ms <- findStream conn sid
    case ms of
      Just s -> reassembleStream s off dat fin
      Nothing -> do
          s <- insertStream conn sid
          putInput conn $ InpNewStream s
          reassembleStream s off dat fin

findStream :: Connection -> StreamId -> IO (Maybe Stream)
findStream Connection{..} sid = do
    -- reader and sender do not insert the same StreamState
    -- at the same time.
    StreamTable tbl0 <- readIORef streamTable
    return $ Map.lookup sid tbl0

insertStream :: Connection -> StreamId -> IO Stream
insertStream Connection{..} sid = do
    s <- newStream sid outputQ
    atomicModifyIORef streamTable $ ins s
    return s
  where
    ins s (StreamTable tbl) = (stbl, ())
      where
        stbl = StreamTable $ Map.insert sid s tbl

----------------------------------------------------------------

initialCryptoStreamId,handshakeCryptoStreamId,rtt1CryptoStreamId :: StreamId
initialCryptoStreamId   = -1
handshakeCryptoStreamId = -2
rtt1CryptoStreamId      = -3

toCryptoStreamId :: EncryptionLevel -> StreamId
toCryptoStreamId InitialLevel   = initialCryptoStreamId
toCryptoStreamId RTT0Level      = error "toCryptoStreamId"
toCryptoStreamId HandshakeLevel = handshakeCryptoStreamId
toCryptoStreamId RTT1Level      = rtt1CryptoStreamId

----------------------------------------------------------------

insertCryptoStreams :: Connection -> IO ()
insertCryptoStreams conn = do
    void $ insertStream conn initialCryptoStreamId
    void $ insertStream conn handshakeCryptoStreamId
    void $ insertStream conn rtt1CryptoStreamId

-- FIXME:: deleteCryptoStreams

----------------------------------------------------------------

getCryptoOffset :: Connection -> EncryptionLevel -> Int -> IO Offset
getCryptoOffset conn lvl len = do
    let sid = toCryptoStreamId lvl
    Just s <- findStream conn sid
    getStreamOffset s len

putInputCrypto :: Connection -> EncryptionLevel -> Offset -> StreamData -> IO ()
putInputCrypto conn lvl off cdat = do
    let sid = toCryptoStreamId lvl
    Just s <- findStream conn sid
    (dats, _) <- isFragmentTop s off cdat False
    mapM_ (\d -> putCrypto conn $ InpHandshake lvl d) dats
