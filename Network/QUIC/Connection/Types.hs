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

data ConnectionState = Handshaking | Established | Closing CloseState deriving (Eq, Show)

data CloseState = CloseState {
    closeSent     :: Bool
  , closeReceived :: Bool
  } deriving (Eq, Show)

----------------------------------------------------------------

type WindowSize = Int

data Stream = Stream {
    streamId     :: StreamId
  , streamWindow :: TVar WindowSize
  , streamState  :: StreamState
  }

-- fixme: 65536
newStream :: StreamId -> IO Stream
newStream sid = Stream sid <$> newTVarIO 65536 <*> newStreamState

----------------------------------------------------------------

data StreamInfo = StreamInfo {
    siOff :: Offset
  , siFin :: Fin
  } deriving (Eq, Show)

emptyStreamInfo :: StreamInfo
emptyStreamInfo = StreamInfo 0 False

data Reassemble = Reassemble StreamData Offset Int deriving (Eq, Show)

data StreamState = StreamState {
    sstx :: IORef StreamInfo
  , ssrx :: IORef StreamInfo
  , ssreass :: IORef [Reassemble]
  }

newStreamState :: IO StreamState
newStreamState = StreamState <$> newIORef emptyStreamInfo
                             <*> newIORef emptyStreamInfo
                             <*> newIORef []

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

data RoleInfo = ClientInfo { connClientCntrl    :: ClientController
                           , clientInitialToken :: Token -- new or retry token
                           , resumptionInfo     :: ResumptionInfo
                           }
              | ServerInfo { connServerCntrl :: ServerController
                           , tokenManager    :: ~CT.TokenManager
                           , registerCID     :: CID -> Connection -> IO ()
                           , unregisterCID   :: CID -> IO ()
                           , askRetry        :: Bool
                           , mainThreadId    :: ~ThreadId
                           }

defaultClientRoleInfo :: RoleInfo
defaultClientRoleInfo = ClientInfo {
    connClientCntrl = nullClientController
  , clientInitialToken = emptyToken
  , resumptionInfo = defaultResumptionInfo
  }

defaultServerRoleInfo :: RoleInfo
defaultServerRoleInfo = ServerInfo {
    connServerCntrl = nullServerController
  , tokenManager = undefined
  , registerCID = \_ _ -> return ()
  , unregisterCID = \_ -> return ()
  , askRetry = False
  , mainThreadId = undefined
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
  , connClose         :: Close
  , connDebugLog      :: LogAction
  , connQLog          :: QlogMsg -> IO ()
  -- Manage
  , threadIds         :: IORef [Weak ThreadId]
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
  -- TLS
  , encryptionLevel   :: TVar EncryptionLevel -- to synchronize
  , pendingHandshake  :: TVar [CryptPacket]
  , pendingRTT1       :: TVar [CryptPacket]
  , iniSecrets        :: IORef (TrafficSecrets InitialSecret)
  , elySecInfo        :: IORef EarlySecretInfo
  , hndSecInfo        :: IORef HandshakeSecretInfo
  , appSecInfo        :: IORef ApplicationSecretInfo
  -- WriteBuffer
  , headerBuffer      :: Buffer
  , headerBufferSize  :: BufferSize
  , payloadBuffer     :: Buffer
  , payloadBufferSize :: BufferSize
  -- Misc
  , nextVersion       :: IORef (Maybe Version)
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
        -- TLS
        <*> newTVarIO InitialLevel
        <*> newTVarIO []
        <*> newTVarIO []
        <*> newIORef isecs
        <*> newIORef (EarlySecretInfo defaultCipher (ClientTrafficSecret ""))
        <*> newIORef (HandshakeSecretInfo defaultCipher defaultTrafficSecrets)
        <*> newIORef (ApplicationSecretInfo FullHandshake Nothing defaultTrafficSecrets)
        <*> mallocBytes 256
        <*> return 256
        <*> mallocBytes 1280
        <*> return 1280
        <*> newIORef Nothing
  where
    initialRoleInfo
      | rl == Client = defaultClientRoleInfo
      | otherwise    = defaultServerRoleInfo

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

serverConnection :: ServerConfig -> Version -> CID -> CID -> OrigCID
                 -> LogAction -> (QlogMsg -> IO ()) -> Close
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
serverConnection ServerConfig{..} ver myCID peerCID origCID debugLog qLog cls sref = do
    let isecs = case origCID of
          OCFirst oCID -> initialSecrets ver oCID
          OCRetry _    -> initialSecrets ver myCID
    newConnection Server ver myCID peerCID debugLog qLog cls sref isecs

----------------------------------------------------------------

isClient :: Connection -> Bool
isClient Connection{..} = role == Client

isServer :: Connection -> Bool
isServer Connection{..} = role == Server
