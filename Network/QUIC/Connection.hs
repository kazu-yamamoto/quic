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
  , isConnectionOpen
  , isConnectionEstablished
  , isConnection1RTTReady
  , setConnection0RTTReady
  , setConnection1RTTReady
  , setConnectionEstablished
  , setCloseSent
  , setCloseReceived
  , isCloseSent
  , wait0RTTReady
  , wait1RTTReady
  , waitEstablished
  , waitClosed
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
  , takeSendStreamQSTM
  , takeSendBlockQSTM
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
  , connLDCC
  , headerBuffer
  , payloadBuffer
  , Input(..)
  , Crypto(..)
  , Output(..)
  -- In this module
  , exitConnection
  , sendConnectionClose
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
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Types

exitConnection :: Connection -> QUICError -> IO ()
exitConnection Connection{..} ue = E.throwTo connThreadId ue

sendConnectionClose :: Connection -> Frame -> IO ()
sendConnectionClose conn frame = do
    lvl <- getEncryptionLevel conn
    putOutput conn $ OutControl lvl [frame]
    setCloseSent conn
