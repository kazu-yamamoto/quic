module Network.QUIC.Connection.StreamTable where

import Data.IORef
import qualified Data.Map.Strict as Map

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

setStreamOffset :: Connection -> StreamID -> Offset -> IO ()
setStreamOffset conn sid off = atomicModifyIORef' (streamTable conn) alter
  where
    alter (StreamTable tbl) = (StreamTable (Map.alter create sid tbl), ())
    create _ = Just (StreamState off)

modifyStreamOffset :: Connection -> StreamID -> Int -> IO Offset
modifyStreamOffset conn sid len = atomicModifyIORef' (streamTable conn) modify
  where
    modify (StreamTable tbl) = update tbl
    update tbl = case Map.updateLookupWithKey add sid tbl of
      (Nothing,                tbl') -> (StreamTable tbl', 0)
      (Just (StreamState new), tbl') -> (StreamTable tbl', new - len)
    add _ (StreamState off) = Just (StreamState (off + len))

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

setCryptoOffset :: Connection -> EncryptionLevel -> Offset -> IO ()
setCryptoOffset conn lvl len = setStreamOffset conn (toCryptoStreamID lvl) len

modifyCryptoOffset :: Connection -> EncryptionLevel -> Int -> IO Offset
modifyCryptoOffset conn lvl len = modifyStreamOffset conn (toCryptoStreamID lvl) len
