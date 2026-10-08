{-# LANGUAGE PatternSynonyms #-}

-- | This main module provides APIs for QUIC.
--
-- The -threaded option must be specified to GHC to use this library.
--
-- On Windows the native I/O manager must be selected as well, with
-- @-with-rtsopts=--io-manager=native@ or @+RTS --io-manager=native@.
-- Under the other one (MIO) a handshake does not complete.  A library
-- cannot choose this, so the application has to.
module Network.QUIC (
    -- * Connection
    Connection,
    abortConnection,

    -- * Stream
    Stream,
    StreamId,
    streamId,

    -- ** Category
    isClientInitiatedBidirectional,
    isServerInitiatedBidirectional,
    isClientInitiatedUnidirectional,
    isServerInitiatedUnidirectional,

    -- ** Opening
    stream,
    unidirectionalStream,
    acceptStream,

    -- ** Closing
    closeStream,
    shutdownStream,
    resetStream,
    stopStream,

    -- * IO
    recvStream,
    resetReceived,
    sendStream,
    sendStreamMany,
    sendDatagram,
    recvDatagram,
    recvDatagramMany,
    recvDatagramSTM,

    -- * Information
    ConnectionInfo,
    getConnectionInfo,
    version,
    cipher,
    alpn,
    handshakeMode,
    retry,
    localSockAddr,
    remoteSockAddr,
    localCID,
    remoteCID,

    -- * Statistics
    ConnectionStats,
    getConnectionStats,
    txBytes,
    rxBytes,

    -- * Synchronization
    wait0RTTReady,
    wait1RTTReady,
    waitEstablished,

    -- * Exceptions and Errors
    QUICException (..),
    TransportError (
        ..,
        NoError,
        InternalError,
        ConnectionRefused,
        FlowControlError,
        StreamLimitError,
        StreamStateError,
        FinalSizeError,
        FrameEncodingError,
        TransportParameterError,
        ConnectionIdLimitError,
        ProtocolViolation,
        InvalidToken,
        ApplicationError,
        CryptoBufferExceeded,
        KeyUpdateError,
        AeadLimitReached,
        NoViablePath
    ),
    cryptoError,
    ApplicationProtocolError (..),
) where

import Network.QUIC.Connection
import Network.QUIC.IO
import Network.QUIC.Info
import Network.QUIC.Stream
import Network.QUIC.Types
import Network.QUIC.Types.Info
