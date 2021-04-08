{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection (
    Connection
  , clientConnection
  , serverConnection
  -- * IO
  , connDebugLog
  , connQLog
  -- * Packet numbers
  , nextPacketNumber
  , setPeerPacketNumber
  , getPeerPacketNumber
  -- * Crypto
  , setEncryptionLevel
  , waitEncryptionLevel
  , putOffCrypto
  , getCipher
  , setCipher
  , getApplicationProtocol
  , getTLSMode
  , setNegotiated
  , dropSecrets
  , Coder(..)
  , initializeCoder
  , initializeCoder1RTT
  , updateCoder1RTT
  , getCoder
  , Protector(..)
  , getProtector
  , getCurrentKeyPhase
  , setCurrentKeyPhase
  -- * Migration
  , getMyCID
  , getMyCIDs
  , getMyCIDSeqNum
  , getPeerCID
  , isMyCID
  , myCIDsInclude
  , shouldUpdateMyCID
  , shouldUpdatePeerCID
  , resetPeerCID
  , getNewMyCID
  , setMyCID
  , retirePeerCID
  , setPeerCIDAndRetireCIDs
  , retireMyCID
  , addPeerCID
  , choosePeerCID
  , choosePeerCIDForPrivacy
  , setPeerStatelessResetToken
  , isStatelessRestTokenValid
  , setMigrationStarted
  , isPathValidating
  , checkResponse
  , validatePath
  -- * Misc
  , setVersion
  , getVersion
  , getSockInfo
  , setSockInfo
  , killHandshaker
  , setKillHandshaker
  , clearKillHandshaker
  , getPeerAuthCIDs
  , setPeerAuthCIDs
  , getMyParameters
  , getPeerParameters
  , setPeerParameters
  , delayedAck
  , resetDealyedAck
  , setMaxPacketSize
  , addResource
  , freeResources
  , addThreadIdResource
  , readMinIdleTimeout
  , setMinIdleTimeout
  -- * State
  , isConnectionEstablished
  , isConnection1RTTReady
  , setConnection0RTTReady
  , setConnection1RTTReady
  , setConnectionEstablished
  , setConnectionClosing
  , setCloseSent
  , setCloseReceived
  , isCloseSent
  , isCloseReceived
  , isClosed
  , wait0RTTReady
  , wait1RTTReady
  , waitEstablished
  , waitClosed
  , readConnectionFlowTx
  , addTxData
  , getTxData
  , setTxMaxData
  , getTxMaxData
  , addRxData
  , getRxData
  , addRxMaxData
  , getRxMaxData
  , getRxDataWindow
  , addTxBytes
  , getTxBytes
  , addRxBytes
  , getRxBytes
  , setAddressValidated
  , waitAntiAmplificationFree
  , checkAntiAmplificationFree
  -- * Stream
  , getMyNewStreamId
  , getMyNewUniStreamId
  , setMyMaxStreams
  , setMyUniMaxStreams
  , getPeerMaxStreams
  -- * StreamTable
  , getStream
  , findStream
  , addStream
  , delStream
  , initialRxMaxStreamData
  , setupCryptoStreams
  , clearCryptoStream
  , getCryptoStream
  -- * Queue
  , takeInput
  , putInput
  , takeCrypto
  , putCrypto
  , takeOutputSTM
  , tryPeekOutput
  , putOutput
  , takeSendStreamQ
  , takeSendStreamQSTM
  , tryPeekSendStreamQ
  , putSendStreamQ
  , readMigrationQ
  , writeMigrationQ
  -- * Role
  , setToken
  , getToken
  , getResumptionInfo
  , setRetried
  , getRetried
  , setResumptionSession
  , setNewToken
  , setRegister
  , getRegister
  , getUnregister
  , setTokenManager
  , getTokenManager
  , setMainThreadId
  , getMainThreadId
  , setCertificateChain
  , getCertificateChain
  -- Types
  , connThreadId
  , connHooks
  , Hooks(..)
  , connLDCC
  , Input(..)
  , Crypto(..)
  , Output(..)
  -- In this module
  , exitConnection
  , exitConnectionByStream
  , sendCCFrame
  , sendCCFrameAndBreak
  , isConnectionOpen
  , sendFrames
  , abortConnection
  ) where

import qualified Control.Exception as E

import Network.QUIC.Config
import Network.QUIC.Connection.Crypto
import Network.QUIC.Connection.Migration
import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Role
import Network.QUIC.Connection.State
import Network.QUIC.Connection.Stream
import Network.QUIC.Connection.StreamTable
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Stream
import Network.QUIC.Timeout
import Network.QUIC.Types

-- | Closing a connection.
exitConnection :: Connection -> QUICException -> IO a
exitConnection _ ue = E.throwIO ue

exitConnectionByStream :: Stream -> QUICException -> IO a
exitConnectionByStream strm ue = exitConnection (streamConnection strm) ue

sendFrames :: Connection -> EncryptionLevel -> [Frame] -> IO ()
sendFrames conn lvl frames = putOutput conn $ OutControl lvl frames Nothing

sendCCFrame :: Connection -> EncryptionLevel -> TransportError -> ShortByteString -> FrameType -> IO ()
sendCCFrame conn lvl err desc ftyp = do
    putOutput conn $ OutControl lvl [frame] $ Just quicexc
    setCloseSent conn
 where
    frame = ConnectionClose err ftyp desc
    quicexc = TransportErrorIsSent err desc

sendCCFrameAndBreak :: Connection -> EncryptionLevel -> TransportError -> ShortByteString -> FrameType -> IO ()
sendCCFrameAndBreak conn lvl err desc ftyp = do
    sendCCFrame conn lvl err desc ftyp
    E.throwIO BreakForever

-- | Checking if a connection is open.
isConnectionOpen :: Connection -> IO Bool
isConnectionOpen = isConnOpen

-- | Closing a connection with an error code.
--   A specified error code is sent to the peer and
--   'ApplicationProtocolErrorIsSent' is thrown to the main thread
--   of this connection.
abortConnection :: Connection -> ApplicationProtocolError -> IO a
abortConnection conn err = do
    lvl <- getEncryptionLevel conn
    putOutput conn $ OutControl lvl [frame] $ Just quicexc
    setCloseSent conn
    delay $ Microseconds 100000
    E.throwIO quicexc -- fixme
  where
    frame = ConnectionCloseApp err ""
    quicexc = ApplicationProtocolErrorIsSent err ""
