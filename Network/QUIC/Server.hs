{-# LANGUAGE PatternSynonyms #-}

-- | This main module provides APIs for QUIC servers.
module Network.QUIC.Server (
  -- * Running a QUIC server
    run
  , ServerConfig(..)
  , defaultServerConfig
  , stop
  -- * Connection
  , Connection
  , abortConnection
  -- * Stream
  , Stream
  , stream
  , unidirectionalStream
  , streamId
  , StreamId
  , closeStream
  , shutdownStream
  , resetStream
  , stopStream
  , acceptStream
  -- * IO
  , recvStream
  , sendStream
  , sendStreamMany
  -- * Types
  , connDebugLog
  , DebugLogger
  -- ** Stream type
  , isClientInitiatedBidirectional
  , isServerInitiatedBidirectional
  , isClientInitiatedUnidirectional
  , isServerInitiatedUnidirectional
  -- ** Version
  , Version(.., Version1)
  -- ** Connection ID
  , CID
  , fromCID
  -- ** Parameters
  , Parameters(..)
  , defaultParameters
  -- ** Hook
  , Hooks(..)
  , defaultHooks
  -- * Information
  , ConnectionInfo(..)
  , getConnectionInfo
  , ResumptionInfo
  , getResumptionInfo
  , isResumptionPossible
  , is0RTTPossible
  -- * Statistics
  , ConnectionStats(..)
  , getConnectionStats
  -- * Exceptions and Errors
  , QUICException(..)
  , TransportError(.., NoError, InternalError, ConnectionRefused, FlowControlError, StreamLimitError, StreamStateError, FinalSizeError, FrameEncodingError, TransportParameterError, ConnectionIdLimitError, ProtocolViolation, InvalidToken, ApplicationError, CryptoBufferExceeded, KeyUpdateError, AeadLimitReached, NoViablePath)
  , cryptoError
  , ApplicationProtocolError(..)
  -- * Synchronization
  , wait0RTTReady
  , wait1RTTReady
  , waitEstablished
  ) where

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.IO
import Network.QUIC.Info
import Network.QUIC.Logger
import Network.QUIC.Parameters
import Network.QUIC.Server.Run
import Network.QUIC.Stream
import Network.QUIC.Types
