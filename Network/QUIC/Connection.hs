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
  , sendFrames
  , closeConnection
  , abortConnection
  ) where

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
import Network.QUIC.Types

sendFrames :: Connection -> EncryptionLevel -> [Frame] -> IO ()
sendFrames conn lvl frames = putOutput conn $ OutControl lvl frames $ return ()

closeConnection :: TransportError -> ReasonPhrase -> IO ()
closeConnection err desc = E.throwIO quicexc
  where
    quicexc = TransportErrorIsSent err desc

abortConnection :: Connection -> ApplicationProtocolError -> ReasonPhrase -> IO ()
abortConnection conn err desc = E.throwTo (mainThreadId conn) quicexc
  where
    quicexc = ApplicationProtocolErrorIsSent err desc
