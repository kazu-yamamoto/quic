{-# LANGUAGE RecordWildCards #-}

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
getStreamOffset Connection{..} sid len = do
    -- reader and sender do not insert the same StreamState
    -- at the same time.
    StreamTable tbl0 <- readIORef streamTable
    StreamState{..} <- case Map.lookup sid tbl0 of
      Nothing -> do
          ss <- newStreamState
          atomicModifyIORef streamTable $ \(StreamTable tbl) ->
            (StreamTable $ Map.insert sid ss tbl, ())
          return ss
      Just ss -> return ss
    -- sstx is modified by only sender
    StreamInfo off fin <- readIORef sstx
    writeIORef sstx $ StreamInfo (off + len) fin
    return off

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
