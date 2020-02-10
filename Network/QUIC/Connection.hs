module Network.QUIC.Connection (
    Connection
  , clientConnection
  , serverConnection
  , SendMany
  , Receive
  , LogAction
  , isClient
  -- * Backend
  , connSend
  , connRecv
  , connClose
  , connLog
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
  -- * Misc
  , setVersion
  , getVersion
  , setMyCID
  , getMyCID
  , setPeerCID
  , getPeerCID
  , setThreadIds
  , clearThreads
  -- * Transmit
  , keepPlainPacket
  , releasePlainPacket
  , releasePlainPacketRemoveAcks
  , getRetransmissions
  , MilliSeconds(..)
  -- * State
  , setConnectionOpen
  , isConnectionOpen
  , setCloseSent
  , setCloseReceived
  , isCloseSent
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
  , getUnregister
  , setTokenManager
  , getTokenManager
  , setMainThreadId
  , getMainThreadId
  ) where

import Network.QUIC.Connection.Crypto
import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Role
import Network.QUIC.Connection.State
import Network.QUIC.Connection.StreamTable
import Network.QUIC.Connection.Transmit
import Network.QUIC.Connection.Types
