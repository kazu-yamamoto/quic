module Network.QUIC.Connection.StreamTable (
    getStreamOffset
  , getCryptoOffset
  ) where

import Data.IORef
import qualified Data.Map.Strict as Map

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

getStreamOffset :: Connection -> StreamID -> Int -> IO Offset
getStreamOffset conn sid len = atomicModifyIORef' (streamTable conn) modify
  where
    modify (StreamTable tbl) = case Map.lookup sid tbl of
      Nothing                -> let s = StreamState len
                                    tbl' = StreamTable $ Map.insert sid s tbl
                                in (tbl', 0)
      Just (StreamState off) -> let s = StreamState (off + len)
                                    adj _ = s
                                    tbl' = StreamTable $ Map.adjust adj sid tbl
                                in (tbl', off)

----------------------------------------------------------------

initialCryptoStreamID,handshakeCryptoStreamID,rtt1CryptoStreamID :: StreamID
initialCryptoStreamID   = -1
handshakeCryptoStreamID = -2
rtt1CryptoStreamID      = -3

toCryptoStreamID :: EncryptionLevel -> StreamID
toCryptoStreamID InitialLevel   = initialCryptoStreamID
toCryptoStreamID RTT0Level      = error "toCryptoStreamID"
toCryptoStreamID HandshakeLevel = handshakeCryptoStreamID
toCryptoStreamID RTT1Level      = rtt1CryptoStreamID

----------------------------------------------------------------

getCryptoOffset :: Connection -> EncryptionLevel -> Int -> IO Offset
getCryptoOffset conn lvl len = getStreamOffset conn (toCryptoStreamID lvl) len
