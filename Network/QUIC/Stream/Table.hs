{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Stream.Table (
    StreamTable,
    emptyStreamTable,
    lookupStream,
    insertStream,
    deleteStream,
    insertCryptoStreams,
    deleteCryptoStream,
    lookupCryptoStream,
) where

import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as Map

import {-# SOURCE #-} Network.QUIC.Connection.Types
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

deleteStream :: StreamId -> StreamTable -> StreamTable
deleteStream sid (StreamTable tbl) = StreamTable $ Map.delete sid tbl

----------------------------------------------------------------

initialCryptoStreamId, handshakeCryptoStreamId, rtt1CryptoStreamId :: StreamId
initialCryptoStreamId = -1
handshakeCryptoStreamId = -2
rtt1CryptoStreamId = -3

toCryptoStreamId :: EncryptionLevel -> StreamId
toCryptoStreamId InitialLevel = initialCryptoStreamId
-- This is to generate an error packet of CRYPTO in 0-RTT
toCryptoStreamId RTT0Level = rtt1CryptoStreamId
toCryptoStreamId HandshakeLevel = handshakeCryptoStreamId
toCryptoStreamId RTT1Level = rtt1CryptoStreamId

----------------------------------------------------------------

insertCryptoStreams :: Connection -> StreamTable -> IO StreamTable
insertCryptoStreams conn stbl = do
    strm1 <- newStream conn initialCryptoStreamId 0 0
    strm2 <- newStream conn handshakeCryptoStreamId 0 0
    strm3 <- newStream conn rtt1CryptoStreamId 0 0
    return $
        insertStream initialCryptoStreamId strm1 $
            insertStream handshakeCryptoStreamId strm2 $
                insertStream rtt1CryptoStreamId strm3 stbl

deleteCryptoStream :: EncryptionLevel -> StreamTable -> StreamTable
deleteCryptoStream InitialLevel = deleteStream initialCryptoStreamId
deleteCryptoStream RTT0Level = deleteStream rtt1CryptoStreamId
deleteCryptoStream HandshakeLevel = deleteStream handshakeCryptoStreamId
deleteCryptoStream RTT1Level = deleteStream rtt1CryptoStreamId

----------------------------------------------------------------

lookupCryptoStream :: EncryptionLevel -> StreamTable -> Maybe Stream
lookupCryptoStream lvl stbl = lookupStream sid stbl
  where
    sid = toCryptoStreamId lvl
