module Network.QUIC.Connection (
    Connection
  , clientConnection
  , serverConnection
  , isClient
  , isServer
  -- * Backend
  , connClose
  , connDebugLog
  , connQLog
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
  , checkResponse
  , validatePath
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
  -- Qlog
  , qlogReceived
  , qlogSent
  , qlogDropped
  , qlogRecvInitial
  , qlogSentRetry
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
import Network.QUIC.Connection.Qlog
