{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}

module Network.QUIC.Connection.Types where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Crypto.Token as CT
import Data.Hourglass
import Data.IORef
import Data.IntMap (IntMap)
import qualified Data.IntMap as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Data.X509 (CertificateChain)
import Foreign.Marshal.Alloc (mallocBytes)
import Network.Socket (Socket)
import Network.TLS.QUIC
import System.Mem.Weak

import Network.QUIC.Config
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

data Role = Client | Server deriving (Eq, Show)

----------------------------------------------------------------

data ConnectionState = Handshaking
                     | ReadyFor0RTT
                     | ReadyFor1RTT
                     | Established
                     | Closing CloseState
                     deriving (Eq, Ord, Show)

data CloseState = CloseState {
    closeSent     :: Bool
  , closeReceived :: Bool
  } deriving (Eq, Ord, Show)

----------------------------------------------------------------

newtype StreamTable = StreamTable (IntMap Stream)

emptyStreamTable :: StreamTable
emptyStreamTable = StreamTable Map.empty

----------------------------------------------------------------

newtype PeerPacketNumbers = PeerPacketNumbers (Set PacketNumber)
                          deriving (Eq, Show)

emptyPeerPacketNumbers :: PeerPacketNumbers
emptyPeerPacketNumbers = PeerPacketNumbers Set.empty

type InputQ  = TQueue Input
type OutputQ = TQueue Output
type RetransDB = [Retrans]
data Retrans = Retrans {
    retransTime          :: ElapsedP
  , retransLevel         :: EncryptionLevel
  , retransPacketNumbers :: [PacketNumber]
  , retransPlainPacket   :: PlainPacket
  , retransACKs          :: PeerPacketNumbers
  }

dummySecrets :: TrafficSecrets a
dummySecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

----------------------------------------------------------------

data RoleInfo = ClientInfo { clientInitialToken :: Token -- new or retry token
                           , resumptionInfo     :: ResumptionInfo
                           }
              | ServerInfo { tokenManager    :: ~CT.TokenManager
                           , registerCID     :: CID -> Connection -> IO ()
                           , unregisterCID   :: CID -> IO ()
                           , askRetry        :: Bool
                           , mainThreadId    :: ~ThreadId
                           , certChain       :: Maybe CertificateChain
                           }

defaultClientRoleInfo :: RoleInfo
defaultClientRoleInfo = ClientInfo {
    clientInitialToken = emptyToken
  , resumptionInfo = defaultResumptionInfo
  }

defaultServerRoleInfo :: RoleInfo
defaultServerRoleInfo = ServerInfo {
    tokenManager = undefined
  , registerCID = \_ _ -> return ()
  , unregisterCID = \_ -> return ()
  , askRetry = False
  , mainThreadId = undefined
  , certChain = Nothing
  }

-- fixme: limitation
data CIDDB = CIDDB {
    usedCIDInfo :: CIDInfo
  , cidInfos    :: [CIDInfo]
  , nextSeqNum  :: Int  -- only for mine
  } deriving (Show)

newCIDDB :: CID -> CIDDB
newCIDDB cid = CIDDB {
    usedCIDInfo = cidInfo
  , cidInfos    = [cidInfo]
  , nextSeqNum  = 1
  }
  where
    cidInfo = CIDInfo 0 cid (StatelessResetToken "")

----------------------------------------------------------------

data MigrationStatus = SendChallenge [PathData]
                     | RecvResponse
                     | NonMigration
                     deriving (Eq, Show)

----------------------------------------------------------------

-- | A quic connection to carry multiple streams.
data Connection = Connection {
    role              :: Role
  , roleInfo          :: IORef RoleInfo
  , quicVersion       :: IORef Version
  -- Actions
  , closeSockets      :: Close
  , connDebugLog      :: LogAction
  , connQLog          :: QlogMsg -> IO ()
  -- Manage
  , threadIds         :: IORef [Weak ThreadId]
  , killHandshakerAct :: IORef (IO ())
  , sockInfo          :: IORef (Socket,RecvQ)
  -- Mine
  , myCIDDB           :: IORef CIDDB
  , migrationStatus   :: TVar MigrationStatus
  -- Peer
  , peerCIDDB         :: TVar CIDDB
  , peerParams        :: IORef Parameters
  -- Queues
  , inputQ            :: InputQ
  , cryptoQ           :: InputQ
  , outputQ           :: OutputQ
  , retransDB         :: IORef RetransDB
  -- State
  , connectionState   :: TVar ConnectionState
  , packetNumber      :: IORef PacketNumber      -- squeezing three to one
  , peerPacketNumbers :: IORef PeerPacketNumbers -- squeezing three to one
  , streamTable       :: IORef StreamTable
  , myStreamId        :: IORef StreamId
  , myUniStreamId     :: IORef StreamId
  , peerStreamId      :: IORef StreamId
  -- TLS
  , encryptionLevel   :: TVar EncryptionLevel -- to synchronize
  , pendingHandshake  :: TVar [CryptPacket]
  , pendingRTT0       :: TVar [CryptPacket]
  , pendingRTT1       :: TVar [CryptPacket]
  , iniSecrets        :: IORef (TrafficSecrets InitialSecret)
  , elySecInfo        :: IORef EarlySecretInfo
  , hndSecInfo        :: IORef HandshakeSecretInfo
  , appSecInfo        :: IORef ApplicationSecretInfo
  , hndMode           :: IORef HandshakeMode13
  , appProto          :: IORef (Maybe NegotiatedProtocol)
  -- WriteBuffer
  , headerBuffer      :: Buffer
  , headerBufferSize  :: BufferSize
  , payloadBuffer     :: Buffer
  , payloadBufferSize :: BufferSize
  }

newConnection :: Role -> Version -> CID -> CID
              -> LogAction -> (QlogMsg -> IO ()) -> Close
              -> IORef (Socket,RecvQ)
              -> TrafficSecrets InitialSecret
              -> IO Connection
newConnection rl ver myCID peerCID debugLog qLog close sref isecs =
    Connection rl
        <$> newIORef initialRoleInfo
        <*> newIORef ver
        -- Actions
        <*> return close
        <*> return debugLog
        <*> return qLog
        -- Manage
        <*> newIORef []
        <*> newIORef (return ())
        <*> return sref
        -- Mine
        <*> newIORef (newCIDDB myCID)
        <*> newTVarIO NonMigration
        -- Peer
        <*> newTVarIO (newCIDDB peerCID)
        <*> newIORef defaultParameters
        -- Queues
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newIORef []
        -- State
        <*> newTVarIO Handshaking
        <*> newIORef 0
        <*> newIORef (PeerPacketNumbers Set.empty)
        <*> newIORef emptyStreamTable
        <*> newIORef (if isclient then 0 else 1)
        <*> newIORef (if isclient then 2 else 3)
        <*> newIORef (if isclient then 1 else 0)
        -- TLS
        <*> newTVarIO InitialLevel
        <*> newTVarIO []
        <*> newTVarIO []
        <*> newTVarIO []
        <*> newIORef isecs
        <*> newIORef (EarlySecretInfo defaultCipher (ClientTrafficSecret ""))
        <*> newIORef (HandshakeSecretInfo defaultCipher defaultTrafficSecrets)
        <*> newIORef (ApplicationSecretInfo defaultTrafficSecrets)
        <*> newIORef FullHandshake
        <*> newIORef Nothing
        <*> mallocBytes 256
        <*> return 256
        <*> mallocBytes 1280
        <*> return 1280
  where
    isclient = rl == Client
    initialRoleInfo
      | isclient  = defaultClientRoleInfo
      | otherwise = defaultServerRoleInfo

defaultTrafficSecrets :: (ClientTrafficSecret a, ServerTrafficSecret a)
defaultTrafficSecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

----------------------------------------------------------------

clientConnection :: ClientConfig -> Version -> CID -> CID
                 -> LogAction -> (QlogMsg -> IO ()) -> Close
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
clientConnection ClientConfig{..} ver myCID peerCID debugLog qLog cls sref = do
    let isecs = initialSecrets ver peerCID
    newConnection Client ver myCID peerCID debugLog qLog cls sref isecs

serverConnection :: ServerConfig -> Version -> CID -> CID -> AuthCIDs
                 -> LogAction -> (QlogMsg -> IO ()) -> Close
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
serverConnection ServerConfig{..} ver myCID peerCID authCIDs debugLog qLog cls sref = do
    let Just cid = case retrySrcID authCIDs of
                     Nothing -> origDstCID authCIDs
                     Just _  -> initSrcCID authCIDs
        isecs = initialSecrets ver cid
    newConnection Server ver myCID peerCID debugLog qLog cls sref isecs

----------------------------------------------------------------

isClient :: Connection -> Bool
isClient Connection{..} = role == Client

isServer :: Connection -> Bool
isServer Connection{..} = role == Server
