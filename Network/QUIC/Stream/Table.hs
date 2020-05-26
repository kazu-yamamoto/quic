{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Table (
    StreamTable
  , emptyStreamTable
  , lookupStream
  , insertStream
  , insertCryptoStreams
  , cryptoOffset
  , getCryptoData
  ) where

import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as Map

import Network.QUIC.Imports
import Network.QUIC.Stream.Types
import Network.QUIC.Stream.Reass
import Network.QUIC.Types

----------------------------------------------------------------

newtype StreamTable = StreamTable (IntMap Stream)

emptyStreamTable :: StreamTable
emptyStreamTable = StreamTable Map.empty

----------------------------------------------------------------

lookupStream :: StreamId -> StreamTable -> Maybe Stream
lookupStream sid (StreamTable tbl) = Map.lookup sid tbl

insertStream :: StreamId -> Stream -> StreamTable -> StreamTable
insertStream sid strm (StreamTable tbl) = StreamTable $ Map.insert sid strm tbl

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

insertCryptoStreams :: StreamTable -> ChunkQ -> IO StreamTable
insertCryptoStreams stbl q = do
    strm1 <- newStream initialCryptoStreamId   q
    strm2 <- newStream handshakeCryptoStreamId q
    strm3 <- newStream rtt1CryptoStreamId      q
    return $ insertStream initialCryptoStreamId   strm1
           $ insertStream handshakeCryptoStreamId strm2
           $ insertStream rtt1CryptoStreamId      strm3 stbl

----------------------------------------------------------------

cryptoOffset :: EncryptionLevel -> Int -> StreamTable -> IO Offset
cryptoOffset lvl len stbl = getStreamOffset strm len
  where
    sid = toCryptoStreamId lvl
    Just strm = lookupStream sid stbl

getCryptoData :: EncryptionLevel -> Offset -> StreamData -> StreamTable -> IO [CryptoData]
getCryptoData lvl off cdat stbl = fst <$> getStreamData strm off cdat False
  where
    sid = toCryptoStreamId lvl
    Just strm = lookupStream sid stbl
