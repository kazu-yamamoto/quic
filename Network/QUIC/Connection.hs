module Network.QUIC.Connection (
    Connection
  , clientConnection
  , serverConnection
  , isClient
  -- * Backend
  , connClose
  , connDebugLog
  , connQLog
  , elapsedTime
  -- * Packet numbers
  , setPacketNumber
  , getPacketNumber
  , PeerPacketNumbers
  , emptyPeerPacketNumbers
  , getPeerPacketNumbers
  , addPeerPacketNumbers
  , clearPeerPacketNumbers
  , nullPeerPacketNumbers
  , fromPeerPacketNumbers
  -- * Crypto
  , setEncryptionLevel
  , checkEncryptionLevel
  , getPeerParameters
  , setPeerParameters
  , getCipher
  , getTLSMode
  , getTxSecret
  , getRxSecret
  , setInitialSecrets
  , getEarlySecretInfo
  , getHandshakeSecretInfo
  , getApplicationSecretInfo
  , setEarlySecretInfo
  , setHandshakeSecretInfo
  , setApplicationSecretInfo
  , dropSecrets
  -- * Migration
  , getMyCID
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
  , setChallenges
  , waitResponse
  , checkResponse
  -- * Misc
  , setVersion
  , getVersion
  , setThreadIds
  , clearThreads
  , getSockInfo
  , setSockInfo
  -- * Transmit
  , keepPlainPacket
  , releasePlainPacket
  , releasePlainPacketRemoveAcks
  , getRetransmissions
  , MilliSeconds(..)
  -- * State
  , isConnectionOpen
  , isConnectionEstablished
  , setConnectionEstablished
  , setCloseSent
  , setCloseReceived
  , isCloseSent
  , waitEstablished
  , waitClosed
  -- * StreamTable
  , getStreamOffset
  , putInputStream
  , getCryptoOffset
  , putInputCrypto
  , getStreamFin
  , setStreamFin
  -- * Queue
  , takeInput
  , putInput
  , takeCrypto
  , putCrypto
  , takeOutput
  , putOutput
  , putOutputPP
  -- * Role
  , getClientController
  , setClientController
  , clearClientController
  , getServerController
  , setServerController
  , clearServerController
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
  ) where

import Network.QUIC.Connection.Crypto
import Network.QUIC.Connection.Migration
import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Role
import Network.QUIC.Connection.State
import Network.QUIC.Connection.StreamTable
import Network.QUIC.Connection.Transmit
import Network.QUIC.Connection.Types
