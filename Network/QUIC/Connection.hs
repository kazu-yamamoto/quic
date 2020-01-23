module Network.QUIC.Connection (
    Connection
  , clientConnection
  , serverConnection
  , SendMany
  , Receive
  , isClient
  , myCID
  -- * Backend
  , connSend
  , connRecv
  , connClose
  -- * Packet numbers
  , getPacketNumber
  , PeerPacketNumbers
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
  , setPeerCID
  , getPeerCID
  , setThreadIds
  , clearThreads
  -- * Transmit
  , keepOutput
  , releaseOutput
  , releaseOutputRemoveAcks
  , getRetransmissions
  , MilliSeconds(..)
  -- * State
  , setConnectionOpen
  , isConnectionOpen
  , setCloseSent
  , setCloseReceived
  , isCloseSent
  , waitClosed
  -- * Stream
  , setStreamOffset
  , modifyStreamOffset
  , setCryptoOffset
  , modifyCryptoOffset
  -- * Queue
  , takeInput
  , putInput
  , takeCrypto
  , putCrypto
  , takeOutput
  , putOutput
  , putOutput'
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
