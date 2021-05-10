{-# LANGUAGE OverloadedStrings #-}

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
  , waitPeerCID
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
  , setSockAddrs
  , getSockAddrs
  -- Timeout
  , timeouter
  , timeout
  , fire
  , cfire
  , delay
  -- Types
  , connHooks
  , Hooks(..)
  , connLDCC
  , Input(..)
  , Crypto(..)
  , Output(..)
  , setDead
  -- In this module
  , sendErrorCCFrame
  , sendCCFrameAndWait
  , sendCCFrameAndBreak
  , sendFrames
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
    setCloseSent conn
 where
    frame = ConnectionClose err ftyp desc

-- for handshaker
sendErrorCCFrame :: Connection -> EncryptionLevel -> TransportError -> ShortByteString -> Int -> IO ()
sendErrorCCFrame conn lvl err desc ftyp = do
    putOutput conn $ OutControl lvl [frame] $ E.throwIO quicexc
    setCloseSent conn
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
    setCloseSent conn
  where
    frame = ConnectionCloseApp err ""
    quicexc = ApplicationProtocolErrorIsSent err ""
