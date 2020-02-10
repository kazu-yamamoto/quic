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

newtype StreamTable = StreamTable (Map StreamID StreamState)

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

type SendMany = [ByteString] -> IO ()
type Receive  = IO CryptPacket
type LogAction = String -> IO ()

----------------------------------------------------------------

data RoleInfo = ClientInfo { connClientCntrl    :: ClientController
                           , clientInitialToken :: Token -- new or retry token
                           , resumptionInfo     :: ResumptionInfo
                           }
              | ServerInfo { connServerCntrl :: ServerController
                           , tokenManager    :: ~CT.TokenManager
                           , registerCID     :: CID -> IO ()
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
  , registerCID = \_ -> return ()
  , unregisterCID = \_ -> return ()
  , askRetry = False
  , mainThreadId = undefined
  }

----------------------------------------------------------------

-- | A quic connection to carry multiple streams.
data Connection = Connection {
    role              :: Role
  , connSend          :: SendMany
  , connRecv          :: Receive
  , connClose         :: IO ()
  , connLog           :: LogAction
  -- Mine
  , myCID             :: IORef CID
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
  , iniSecrets        :: IORef (TrafficSecrets InitialSecret)
  , elySecInfo        :: IORef EarlySecretInfo
  , hndSecInfo        :: IORef HandshakeSecretInfo
  , appSecInfo        :: IORef ApplicationSecretInfo
  -- Misc
  , roleInfo          :: IORef RoleInfo
  , connVersion       :: IORef Version
  }

newConnection :: Role -> Version -> CID -> CID -> LogAction -> SendMany -> Receive -> IO () -> TrafficSecrets InitialSecret -> IO Connection
newConnection rl ver myCID peerCID logAction send recv cls isecs =
    Connection rl send recv cls logAction
        -- Mine
        <$> newIORef myCID
        <*> newIORef []
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
        <*> newIORef isecs
        <*> newIORef (EarlySecretInfo defaultCipher (ClientTrafficSecret ""))
        <*> newIORef (HandshakeSecretInfo defaultCipher defaultTrafficSecrets)
        <*> newIORef (ApplicationSecretInfo FullHandshake Nothing defaultTrafficSecrets)
        -- Misc
        <*> newIORef initialRoleInfo
        <*> newIORef ver
  where
    initialRoleInfo
      | rl == Client = defaultClientRoleInfo
      | otherwise    = defaultServerRoleInfo

defaultTrafficSecrets :: (ClientTrafficSecret a, ServerTrafficSecret a)
defaultTrafficSecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

----------------------------------------------------------------

clientConnection :: ClientConfig -> Version -> CID -> CID -> LogAction
                 -> SendMany -> Receive -> IO () -> IO Connection
clientConnection ClientConfig{..} ver myCID peerCID logAction send recv cls = do
    let isecs = initialSecrets ver peerCID
    newConnection Client ver myCID peerCID logAction send recv cls isecs

serverConnection :: ServerConfig -> Version -> CID -> CID -> OrigCID -> LogAction
                 -> SendMany -> Receive -> IO () -> IO Connection
serverConnection ServerConfig{..} ver myCID peerCID origCID logAction send recv cls = do
    let isecs = case origCID of
          OCFirst oCID -> initialSecrets ver oCID
          OCRetry _    -> initialSecrets ver myCID
    newConnection Server ver myCID peerCID logAction send recv cls isecs

----------------------------------------------------------------

isClient :: Connection -> Bool
isClient Connection{..} = role == Client
