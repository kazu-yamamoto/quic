{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}

module Network.QUIC.Connection.Types where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Crypto.Token as CT
import Data.Hourglass
import Data.IORef
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Network.TLS.QUIC
import System.Mem.Weak

import Network.QUIC.Config
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

data Role = Client | Server deriving (Eq, Show)

----------------------------------------------------------------

data ConnectionState = NotOpen | Open | Closing CloseState deriving (Eq, Show)

data CloseState = CloseState {
    closeSent     :: Bool
  , closeReceived :: Bool
  } deriving (Eq, Show)

----------------------------------------------------------------

newtype StreamState = StreamState Offset deriving (Eq, Show)

newtype StreamTable = StreamTable (Map StreamID StreamState)
                    deriving (Eq, Show)

emptyStreamTable :: StreamTable
emptyStreamTable = StreamTable Map.empty

----------------------------------------------------------------

newtype PeerPacketNumbers = PeerPacketNumbers (Set PacketNumber)
                          deriving (Eq, Show)

type InputQ  = TQueue Input
type OutputQ = TQueue (Output,[PacketNumber])
type RetransDB = [Retrans]
data Retrans = Retrans {
    retransTime          :: ElapsedP
  , retransLevel         :: EncryptionLevel
  , retransPacketNumbers :: [PacketNumber]
  , retransOutput        :: Output
  , retransACKs          :: PeerPacketNumbers
  }

dummySecrets :: TrafficSecrets a
dummySecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

type SendMany = [ByteString] -> IO ()
type Receive  = IO CryptPacket

----------------------------------------------------------------

data RoleInfo = ClientInfo { connClientCntrl    :: ClientController
                           , clientInitialToken :: Token -- new or retry token
                           , resumptionInfo     :: ResumptionInfo
                           }
              | ServerInfo { connServerCntrl :: ServerController
                           , tokenManager    :: ~CT.TokenManager
                           , routeRegister   :: CID -> IO ()
                           , routeUnregister :: CID -> IO ()
                           , askRetry        :: Bool
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
  , routeRegister = \_ -> return ()
  , routeUnregister = \_ -> return ()
  , askRetry = False
  }

----------------------------------------------------------------

data Connection = Connection {
    role              :: Role
  , myCID             :: CID
  , connSend          :: SendMany
  , connRecv          :: Receive
  , connClose         :: IO ()
  , threadIds         :: IORef [Weak ThreadId]
  -- Peer
  , peerCID           :: IORef CID
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
  , iniSecrets        :: IORef (Maybe (TrafficSecrets InitialSecret))
  , elySecInfo        :: IORef (Maybe EarlySecretInfo)
  , hndSecInfo        :: IORef (Maybe HandshakeSecretInfo)
  , appSecInfo        :: IORef (Maybe ApplicationSecretInfo)
  -- Misc
  , roleInfo          :: IORef RoleInfo
  , connVersion       :: IORef Version
  }

newConnection :: Role -> Version -> CID -> CID -> SendMany -> Receive -> IO () -> IO Connection
newConnection rl ver myCID peerCID send recv cls =
    Connection rl myCID send recv cls
        <$> newIORef []
        -- Peer
        <*> newIORef peerCID
        <*> newIORef defaultParameters
        -- Queues
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newIORef []
        -- State
        <*> newTVarIO NotOpen
        <*> newIORef 0
        <*> newIORef (PeerPacketNumbers Set.empty)
        <*> newIORef emptyStreamTable
        -- TLS
        <*> newTVarIO InitialLevel
        <*> newIORef Nothing
        <*> newIORef Nothing
        <*> newIORef Nothing
        <*> newIORef Nothing
        -- Misc
        <*> newIORef initialRoleInfo
        <*> newIORef ver
  where
    initialRoleInfo
      | rl == Client = defaultClientRoleInfo
      | otherwise    = defaultServerRoleInfo

----------------------------------------------------------------

clientConnection :: ClientConfig -> CID -> CID
                 -> SendMany -> Receive -> IO () -> IO Connection
clientConnection ClientConfig{..} myCID peerCID send recv cls = do
    let ver = head $ confVersions ccConfig -- fixme
    conn <- newConnection Client ver myCID peerCID send recv cls
    let isecs = initialSecrets ver peerCID
    -- overridden in Retry or VersionNegotiation
    writeIORef (iniSecrets conn) $ Just isecs
    return conn

serverConnection :: ServerConfig -> Version -> CID -> CID -> OrigCID
                 -> SendMany -> Receive -> IO () -> IO Connection
serverConnection ServerConfig{..} ver myCID peerCID origCID send recv cls = do
    conn <- newConnection Server ver myCID peerCID send recv cls
    let isecs = case origCID of
          OCFirst oCID -> initialSecrets ver oCID
          OCRetry _    -> initialSecrets ver myCID
    writeIORef (iniSecrets conn) $ Just isecs
    return conn

----------------------------------------------------------------

isClient :: Connection -> Bool
isClient Connection{..} = role == Client
