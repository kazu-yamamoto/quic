{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Connection (
    module Network.QUIC.Connection.PacketNumber
  , module Network.QUIC.Connection.Crypto
  , module Network.QUIC.Connection.Migration
  , module Network.QUIC.Connection.Misc
  , module Network.QUIC.Connection.State
  , module Network.QUIC.Connection.Stream
  , module Network.QUIC.Connection.StreamTable
  , module Network.QUIC.Connection.Queue
  , module Network.QUIC.Connection.Role
  , module Network.QUIC.Connection.Timeout
  , module Network.QUIC.Connection.Types
  -- In this module
  , sendErrorCCFrame
  , sendCCFrameAndWait
  , sendCCFrameAndBreak
  , sendFrames
  , abortConnection
  ) where

import Control.Concurrent
import qualified Control.Exception as E

import Network.QUIC.Connection.Crypto
import Network.QUIC.Connection.Migration
import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Role
import Network.QUIC.Connection.State
import Network.QUIC.Connection.Stream
import Network.QUIC.Connection.StreamTable
import Network.QUIC.Connection.Timeout
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Types

sendFrames :: Connection -> EncryptionLevel -> [Frame] -> IO ()
sendFrames conn lvl frames = putOutput conn $ OutControl lvl frames $ return ()

-- for client
-- sender is killed by race
sendCCFrameAndWait :: Connection -> EncryptionLevel -> TransportError -> ShortByteString -> FrameType -> IO ()
sendCCFrameAndWait conn lvl err desc ftyp = do
    mvar <- newEmptyMVar
    putOutput conn $ OutControl lvl [frame] $ putMVar mvar ()
    _ <- timeout (Microseconds 100000) $ takeMVar mvar
    return ()
 where
    frame = ConnectionClose err ftyp desc

-- for handshaker
sendErrorCCFrame :: Connection -> EncryptionLevel -> TransportError -> ShortByteString -> Int -> IO ()
sendErrorCCFrame conn lvl err desc ftyp = do
    putOutput conn $ OutControl lvl [frame] $ E.throwIO quicexc
 where
    frame = ConnectionClose err ftyp desc
    quicexc = TransportErrorIsSent err desc

-- for receiver. don't receive packets anymore.
sendCCFrameAndBreak :: Connection -> EncryptionLevel -> TransportError -> ShortByteString -> FrameType -> IO ()
sendCCFrameAndBreak conn lvl err desc ftyp = do
    sendErrorCCFrame conn lvl err desc ftyp
    E.throwIO BreakForever

-- | Closing a connection with an error code.
--   A specified error code is sent to the peer and
--   'ApplicationProtocolErrorIsSent' is thrown to the main thread
--   of this connection.
abortConnection :: Connection -> ApplicationProtocolError -> IO ()
abortConnection conn err = do
    lvl <- getEncryptionLevel conn
    mvar <- newEmptyMVar
    putOutput conn $ OutControl lvl [frame] (putMVar mvar () >> E.throwIO quicexc)
    _ <- timeout (Microseconds 100000) $ takeMVar mvar
    return ()
  where
    frame = ConnectionCloseApp err ""
    quicexc = ApplicationProtocolErrorIsSent err ""
