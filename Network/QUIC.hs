{-# LANGUAGE PatternSynonyms #-}

-- | This main module provides APIs for QUIC.
--
-- The -threaded option must be specified to GHC to use this library.
module Network.QUIC (
  -- * Connection
    Connection
  , abortConnection
  -- * Stream
  , Stream
  , StreamId
  , streamId
  -- ** Category
  , isClientInitiatedBidirectional
  , isServerInitiatedBidirectional
  , isClientInitiatedUnidirectional
  , isServerInitiatedUnidirectional
  -- ** Opening
  , stream
  , unidirectionalStream
  , acceptStream
  -- ** Closing
  , closeStream
  , shutdownStream
  , resetStream
  , stopStream
  -- * IO
  , recvStream
  , sendStream
  , sendStreamMany
  -- * Information
  , ConnectionInfo(..)
  , getConnectionInfo
  -- * Statistics
  , ConnectionStats(..)
  , getConnectionStats
  -- * Synchronization
  , wait0RTTReady
  , wait1RTTReady
  , waitEstablished
  -- * Exceptions and Errors
  , QUICException(..)
  , TransportError(.., NoError, InternalError, ConnectionRefused, FlowControlError, StreamLimitError, StreamStateError, FinalSizeError, FrameEncodingError, TransportParameterError, ConnectionIdLimitError, ProtocolViolation, InvalidToken, ApplicationError, CryptoBufferExceeded, KeyUpdateError, AeadLimitReached, NoViablePath)
  , cryptoError
  , ApplicationProtocolError(..)
  ) where

import Network.QUIC.Connection
import Network.QUIC.IO
import Network.QUIC.Info
import Network.QUIC.Stream
import Network.QUIC.Types
