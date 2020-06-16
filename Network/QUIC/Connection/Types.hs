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
  , myParameters      :: Parameters
  -- Peer
  , peerCIDDB         :: TVar CIDDB
  , peerParameters    :: IORef Parameters
  -- Queues
  , inputQ            :: InputQ
  , cryptoQ           :: InputQ
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

newConnection :: Role -> Version -> Parameters
              -> AuthCIDs -> AuthCIDs
              -> LogAction -> (QlogMsg -> IO ()) -> Close
              -> IORef (Socket,RecvQ)
              -> TrafficSecrets InitialSecret
              -> IO Connection
newConnection rl ver myparams myAuthCIDs peerAuthCIDs debugLog qLog close sref isecs = do
    tvarFlowTx <- newTVarIO defaultFlow
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
        <*> return myparams
        -- Peer
        <*> newTVarIO (newCIDDB peerCID)
        <*> newIORef baseParameters
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
        <*> mallocBytes 256
        <*> return 256
        <*> mallocBytes 1280
        <*> return 1280
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

clientConnection :: ClientConfig -> Version -> AuthCIDs -> AuthCIDs
                 -> LogAction -> (QlogMsg -> IO ()) -> Close
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
clientConnection ClientConfig{..} ver myAuthCIDs peerAuthCIDs debugLog qLog cls sref = do
    let Just cid = initSrcCID peerAuthCIDs
        isecs = initialSecrets ver cid
        params = confParameters ccConfig
    newConnection Client ver params myAuthCIDs peerAuthCIDs debugLog qLog cls sref isecs

serverConnection :: ServerConfig -> Version -> AuthCIDs -> AuthCIDs
                 -> LogAction -> (QlogMsg -> IO ()) -> Close
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
serverConnection ServerConfig{..} ver myAuthCIDs peerAuthCIDs debugLog qLog cls sref = do
    let Just cid = case retrySrcCID myAuthCIDs of
                     Nothing -> origDstCID myAuthCIDs
                     Just _  -> retrySrcCID myAuthCIDs
        isecs = initialSecrets ver cid
        params = confParameters scConfig
    newConnection Server ver params myAuthCIDs peerAuthCIDs debugLog qLog cls sref isecs

----------------------------------------------------------------

isClient :: Connection -> Bool
isClient Connection{..} = role == Client

isServer :: Connection -> Bool
isServer Connection{..} = role == Server

----------------------------------------------------------------

data Input = InpNewStream Stream
           | InpHandshake EncryptionLevel ByteString
           | InpTransportError TransportError FrameType ReasonPhrase
           | InpApplicationError ApplicationError ReasonPhrase
           | InpError QUICError
           deriving Show

data Output = OutControl EncryptionLevel [Frame]
            | OutHandshake [(EncryptionLevel,ByteString)]
            | OutPlainPacket PlainPacket
            deriving Show
