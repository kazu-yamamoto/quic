module Network.QUIC.Connection (
    Connection
  , clientConnection
  , serverConnection
  , isClient
  , myCID
  , connSend
  , connRecv
  , connClose
  , inputQ -- fixme
  , outputQ
  , cryptoQ
  --
  , Input(..)
  , Output(..)
  -- * Packet numbers
  , getPacketNumber
  , getPNs
  , addPNs
  , clearPNs
  , nullPNs
  , fromPNs
  -- * Crypto
  , setEncryptionLevel
  , checkEncryptionLevel
  , getClientController
  , setClientController
  , clearClientController
  , getServerController
  , setServerController
  , clearServerController
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
  , setToken
  , getToken
  , getResumptionInfo
  , setRetried
  , getRetried
  , setResumptionSession
  , setNewToken
  , setServerRoleInfo
  , getUnregister
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
  ) where

import Network.QUIC.Connection.Crypto
import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.State
import Network.QUIC.Connection.StreamTable
import Network.QUIC.Connection.Transmit
import Network.QUIC.Connection.Types
