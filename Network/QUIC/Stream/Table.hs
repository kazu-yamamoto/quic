{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Table (
    StreamTable
  , emptyStreamTable
  , lookupStream
  , insertStream
  , insertCryptoStreams
  , cryptoTxOffset
  , getCryptoData
  ) where

import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as Map

import Network.QUIC.Imports
import Network.QUIC.Stream.Misc
import Network.QUIC.Stream.Reass
import Network.QUIC.Stream.Types
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

insertCryptoStreams :: StreamTable -> Shared -> IO StreamTable
insertCryptoStreams stbl shrd = do
    strm1 <- newStream initialCryptoStreamId   shrd
    strm2 <- newStream handshakeCryptoStreamId shrd
    strm3 <- newStream rtt1CryptoStreamId      shrd
    return $ insertStream initialCryptoStreamId   strm1
           $ insertStream handshakeCryptoStreamId strm2
           $ insertStream rtt1CryptoStreamId      strm3 stbl

----------------------------------------------------------------

cryptoTxOffset :: EncryptionLevel -> Int -> StreamTable -> IO Offset
cryptoTxOffset lvl len stbl = getTxStreamOffset strm len
  where
    sid = toCryptoStreamId lvl
    Just strm = lookupStream sid stbl

getCryptoData :: EncryptionLevel -> RxStreamData -> StreamTable -> IO [CryptoData]
getCryptoData lvl rx stbl = fst <$> tryReassemble strm rx
  where
    sid = toCryptoStreamId lvl
    Just strm = lookupStream sid stbl
