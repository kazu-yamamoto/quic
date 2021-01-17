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
  , getCoder
  -- * Migration
  , getMyCID
  , getMyCIDs
  , getMyCIDSeqNum
  , getPeerCID
  , isMyCID
  , myCIDsInclude
  , resetPeerCID
  , getNewMyCID
  , setMyCID
  , retirePeerCID
  , setPeerCIDAndRetireCIDs
  , retireMyCID
  , addPeerCID
  , choosePeerCID
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
  , takeSendBlockQSTM
  , putSendBlockedQ
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
  , headerBuffer
  , payloadBuffer
  , Input(..)
  , Crypto(..)
  , Output(..)
  -- In this module
  , exitConnection
  , sendFrame
  , sendCCandExitConnection
  , isConnectionOpen
  , abortConnection
  ) where

import Control.Concurrent
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
import Network.QUIC.Types

-- | Closing a connection.
--   'QUICException' is thrown to the main thread
--   of this connection.
exitConnection :: Connection -> QUICException -> IO ()
exitConnection Connection{..} ue = E.throwTo connThreadId ue

sendFrame :: Connection -> Frame -> IO ()
sendFrame conn frame = do
    lvl <- getEncryptionLevel conn
    putOutput conn $ OutControl lvl [frame]
    setCloseSent conn

sendCCandExitConnection :: Connection -> TransportError -> ShortByteString -> FrameType -> IO ()
sendCCandExitConnection conn err desc ftyp = do
    sendFrame conn frame
    exitConnection conn quicexc
  where
    frame = ConnectionClose err ftyp desc
    quicexc = TransportErrorIsSent err desc

-- | Checking if a connection is open.
isConnectionOpen :: Connection -> IO Bool
isConnectionOpen = isConnOpen

-- | Closing a connection with an error code.
--   A specified error code is sent to the peer and
--   'ApplicationProtocolErrorIsSent' is thrown to the main thread
--   of this connection.
abortConnection :: Connection -> ApplicationProtocolError -> IO ()
abortConnection conn err = do
    sendFrame conn frame
    threadDelay 100000
    exitConnection conn quicexc
  where
    frame = ConnectionCloseApp err ""
    quicexc = ApplicationProtocolErrorIsSent err ""
