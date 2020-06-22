{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}

module Network.QUIC.Connection.Types where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Crypto.Token as CT
import Data.IORef
import Data.IntPSQ (IntPSQ)
import qualified Data.IntPSQ as IntPSQ
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
import Network.QUIC.Stream
import Network.QUIC.TLS
import Network.QUIC.Time
import Network.QUIC.Types

----------------------------------------------------------------

data Role = Client | Server deriving (Eq, Show)

----------------------------------------------------------------

data ConnectionState = Handshaking
                     | ReadyFor0RTT
                     | ReadyFor1RTT
                     | Established
                     deriving (Eq, Ord, Show)

data CloseState = CloseState {
    closeSent     :: Bool
  , closeReceived :: Bool
  } deriving (Eq, Show)

----------------------------------------------------------------

newtype PeerPacketNumbers = PeerPacketNumbers (Set PacketNumber)
                          deriving (Eq, Show)

emptyPeerPacketNumbers :: PeerPacketNumbers
emptyPeerPacketNumbers = PeerPacketNumbers Set.empty

type InputQ  = TQueue Input
type CryptoQ = TQueue Crypto
type OutputQ = TQueue Output

data RetransDB = RetransDB {
    minPN :: PacketNumber -- ^ If 'keptPackets' is 'IntPSQ.empty',
                          -- 'maxPN' is copied and 1 is added.
  , maxPN :: PacketNumber
  , keptPackets :: IntPSQ TimeMillisecond Retrans
  } deriving Show

emptyRetransDB :: RetransDB
emptyRetransDB = RetransDB 0 0 IntPSQ.empty

data Retrans = Retrans {
    retransPacketNumber :: PacketNumber
  , retransLevel        :: EncryptionLevel
  , retransPlainPacket  :: PlainPacket
  , retransACKs         :: PeerPacketNumbers
  } deriving Show

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

data MigrationState = SendChallenge [PathData]
                    | RecvResponse
                    | NonMigration
                    deriving (Eq, Show)

data Coder = Coder {
    encrypt :: CipherText -> ByteString -> PacketNumber -> [CipherText]
  , decrypt :: CipherText -> ByteString -> PacketNumber -> Maybe PlainText
  , protect   :: Sample -> Mask
  , unprotect :: Sample -> Mask
  }

initialCoder :: Coder
initialCoder = Coder {
    encrypt = \_ _ _ -> []
  , decrypt = \_ _ _ -> Nothing
  , protect   = \_ -> Mask ""
  , unprotect = \_ -> Mask ""
  }

----------------------------------------------------------------

-- | A quic connection to carry multiple streams.
data Connection = Connection {
    role              :: Role
  -- Actions
  , closeSockets      :: Close
  , connDebugLog      :: LogAction
  , connQLog          :: QlogMsg -> IO ()
  , connHooks         :: Hooks
  -- Info
  , roleInfo          :: IORef RoleInfo
  , quicVersion       :: IORef Version
  -- Manage
  , connThreadId      :: ThreadId
  , threadIds         :: IORef [Weak ThreadId]
  , killHandshakerAct :: IORef (IO ())
  , sockInfo          :: IORef (Socket,RecvQ)
  -- Mine
  , myParameters      :: Parameters
  , myCIDDB           :: IORef CIDDB
  -- Peer
  , peerParameters    :: IORef Parameters
  , peerCIDDB         :: TVar CIDDB
  -- Queues
  , inputQ            :: InputQ
  , cryptoQ           :: CryptoQ
  , outputQ           :: OutputQ
  , shared            :: Shared
  , retransDB         :: IORef RetransDB
  , delayedAck        :: IORef Int
  -- State
  , connectionState   :: TVar ConnectionState
  , closeState        :: TVar CloseState
  , packetNumber      :: IORef PacketNumber      -- squeezing three to one
  , peerPacketNumber  :: IORef PacketNumber      -- for RTT1
  , peerPacketNumbers :: IORef PeerPacketNumbers -- squeezing three to one
  , streamTable       :: IORef StreamTable
  , myStreamId        :: IORef StreamId
  , myUniStreamId     :: IORef StreamId
  , peerStreamId      :: IORef StreamId
  , flowTx            :: TVar Flow
  , flowRx            :: IORef Flow
  , migrationState    :: TVar MigrationState
  , maxPacketSize     :: IORef Int
  -- TLS
  , encryptionLevel   :: TVar EncryptionLevel -- to synchronize
  , pendingHandshake  :: TVar [CryptPacket]
  , pendingRTT0       :: TVar [CryptPacket]
  , pendingRTT1       :: TVar [CryptPacket]
  , iniSecrets        :: IORef (TrafficSecrets InitialSecret)
  , elySecInfo        :: IORef EarlySecretInfo
  , hndSecInfo        :: IORef HandshakeSecretInfo
  , appSecInfo        :: IORef ApplicationSecretInfo
  , iniCoder          :: IORef Coder
  , elyCoder          :: IORef Coder
  , hndCoder          :: IORef Coder
  , appCoder          :: IORef Coder
  , hndMode           :: IORef HandshakeMode13
  , appProto          :: IORef (Maybe NegotiatedProtocol)
  , handshakeCIDs     :: IORef AuthCIDs
  -- WriteBuffer
  , headerBuffer      :: Buffer
  , headerBufferSize  :: BufferSize
  , payloadBuffer     :: Buffer
  , payloadBufferSize :: BufferSize
  }

newConnection :: Role
              -> Parameters -> TrafficSecrets InitialSecret
              -> Version -> AuthCIDs -> AuthCIDs
              -> LogAction -> (QlogMsg -> IO ()) -> Hooks -> Close
              -> IORef (Socket,RecvQ)
              -> IO Connection
newConnection rl myparams isecs ver myAuthCIDs peerAuthCIDs debugLog qLog hooks close sref = do
    tvarFlowTx <- newTVarIO defaultFlow
    Connection rl close debugLog qLog hooks
        -- Info
        <$> newIORef initialRoleInfo
        <*> newIORef ver
        -- Manage
        <*> myThreadId
        <*> newIORef []
        <*> newIORef (return ())
        <*> return sref
        -- Mine
        <*> return myparams
        <*> newIORef (newCIDDB myCID)
        -- Peer
        <*> newIORef baseParameters
        <*> newTVarIO (newCIDDB peerCID)
        -- Queues
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newShared tvarFlowTx
        <*> newIORef emptyRetransDB
        <*> newIORef 0
        -- State
        <*> newTVarIO Handshaking
        <*> newTVarIO CloseState { closeSent = False, closeReceived = False }
        <*> newIORef 0
        <*> newIORef 0
        <*> newIORef (PeerPacketNumbers Set.empty)
        <*> newIORef emptyStreamTable
        <*> newIORef (if isclient then 0 else 1)
        <*> newIORef (if isclient then 2 else 3)
        <*> newIORef (if isclient then 1 else 0)
        <*> return tvarFlowTx
        <*> newIORef defaultFlow { flowMaxData = initialMaxData myparams }
        <*> newTVarIO NonMigration
        <*> newIORef defaultQUICPacketSize
        -- TLS
        <*> newTVarIO InitialLevel
        <*> newTVarIO []
        <*> newTVarIO []
        <*> newTVarIO []
        <*> newIORef isecs
        <*> newIORef (EarlySecretInfo defaultCipher (ClientTrafficSecret ""))
        <*> newIORef (HandshakeSecretInfo defaultCipher defaultTrafficSecrets)
        <*> newIORef (ApplicationSecretInfo defaultTrafficSecrets)
        <*> newIORef initialCoder
        <*> newIORef initialCoder
        <*> newIORef initialCoder
        <*> newIORef initialCoder
        <*> newIORef FullHandshake
        <*> newIORef Nothing
        <*> newIORef peerAuthCIDs
        -- WriteBuffer
        <*> mallocBytes maximumQUICHeaderSize
        <*> return      maximumQUICHeaderSize
        <*> mallocBytes maximumUdpPayloadSize
        <*> return      maximumUdpPayloadSize
  where
    isclient = rl == Client
    initialRoleInfo
      | isclient  = defaultClientRoleInfo
      | otherwise = defaultServerRoleInfo
    Just myCID   = initSrcCID myAuthCIDs
    Just peerCID = initSrcCID peerAuthCIDs

defaultTrafficSecrets :: (ClientTrafficSecret a, ServerTrafficSecret a)
defaultTrafficSecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

----------------------------------------------------------------

clientConnection :: ClientConfig
                 -> Version -> AuthCIDs -> AuthCIDs
                 -> LogAction -> (QlogMsg -> IO ()) -> Hooks -> Close
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
clientConnection ClientConfig{..} ver myAuthCIDs peerAuthCIDs =
    newConnection Client params isecs ver myAuthCIDs peerAuthCIDs
  where
    Just cid = initSrcCID peerAuthCIDs
    isecs = initialSecrets ver cid
    params = confParameters ccConfig

serverConnection :: ServerConfig
                 -> Version -> AuthCIDs -> AuthCIDs
                 -> LogAction -> (QlogMsg -> IO ()) -> Hooks -> Close
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
serverConnection ServerConfig{..} ver myAuthCIDs peerAuthCIDs =
    newConnection Server params isecs ver myAuthCIDs peerAuthCIDs
  where
    Just cid = case retrySrcCID myAuthCIDs of
                 Nothing -> origDstCID myAuthCIDs
                 Just _  -> retrySrcCID myAuthCIDs
    isecs = initialSecrets ver cid
    params = confParameters scConfig

----------------------------------------------------------------

isClient :: Connection -> Bool
isClient Connection{..} = role == Client

isServer :: Connection -> Bool
isServer Connection{..} = role == Server

----------------------------------------------------------------

newtype Input = InpStream Stream deriving Show
data   Crypto = InpHandshake EncryptionLevel ByteString deriving Show

data Output = OutControl   EncryptionLevel [Frame]
            | OutHandshake [(EncryptionLevel,ByteString)]
            | OutRetrans   PlainPacket
            deriving Show
