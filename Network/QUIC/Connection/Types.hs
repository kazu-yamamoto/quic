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
import Foreign.Marshal.Alloc (mallocBytes, free)
import Network.Socket (Socket)
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Parameters
import Network.QUIC.Stream
import Network.QUIC.TLS
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

data MigrationState = NonMigration
                    | MigrationStarted
                    | SendChallenge [PathData]
                    | RecvResponse
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

data Negotiated = Negotiated {
      handshakeMode :: HandshakeMode13
    , applicationProtocol :: Maybe NegotiatedProtocol
    , applicationSecretInfo :: ApplicationSecretInfo
    }

initialNegotiated :: Negotiated
initialNegotiated = Negotiated {
      handshakeMode = FullHandshake
    , applicationProtocol = Nothing
    , applicationSecretInfo = ApplicationSecretInfo defaultTrafficSecrets
    }

----------------------------------------------------------------

-- | A quic connection to carry multiple streams.
data Connection = Connection {
    role              :: Role
  -- Actions
  , connDebugLog      :: DebugLogger
  , connQLog          :: QLogger
  , connHooks         :: Hooks
  -- WriteBuffer
  , headerBuffer      :: (Buffer,BufferSize)
  , payloadBuffer     :: (Buffer,BufferSize)
  -- Info
  , roleInfo          :: IORef RoleInfo
  , quicVersion       :: IORef Version
  -- Manage
  , connThreadId      :: ThreadId
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
  , migrationQ        :: MigrationQ
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
  , minIdleTimeout    :: IORef Milliseconds
  -- TLS
  , encryptionLevel   :: TVar EncryptionLevel -- to synchronize
  , pendingQ          :: Array EncryptionLevel (TVar [CryptPacket])
  , ciphers           :: IOArray EncryptionLevel Cipher
  , coders            :: IOArray EncryptionLevel Coder
  , negotiated        :: IORef Negotiated
  , handshakeCIDs     :: IORef AuthCIDs
  -- Resources
  , connResources     :: IORef (IO ())
  }

newConnection :: Role
              -> Parameters
              -> Version -> AuthCIDs -> AuthCIDs
              -> DebugLogger -> QLogger -> Hooks
              -> IORef (Socket,RecvQ)
              -> IO Connection
newConnection rl myparams ver myAuthCIDs peerAuthCIDs debugLog qLog hooks sref = do
    tvarFlowTx <- newTVarIO defaultFlow
    let hlen = maximumQUICHeaderSize
        plen = maximumUdpPayloadSize
    hbuf <- mallocBytes hlen
    pbuf <- mallocBytes plen
    let freeBufs = free hbuf >> free pbuf
    q1 <- newTVarIO []
    q2 <- newTVarIO []
    q3 <- newTVarIO []
    let pendingQueues = array (RTT0Level,RTT1Level) [(RTT0Level,q1),(HandshakeLevel,q2),(RTT1Level,q3)]
    Connection rl debugLog qLog hooks (hbuf,hlen) (pbuf,plen)
        -- Info
        <$> newIORef initialRoleInfo
        <*> newIORef ver
        -- Manage
        <*> myThreadId
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
        <*> newIORef (maxIdleTimeout myparams)
        -- TLS
        <*> newTVarIO InitialLevel
        <*> return pendingQueues
        <*> newArray (InitialLevel,RTT1Level) defaultCipher
        <*> newArray (InitialLevel,RTT1Level) initialCoder
        <*> newIORef initialNegotiated
        <*> newIORef peerAuthCIDs
        -- Resources
        <*> newIORef freeBufs
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
                 -> DebugLogger -> QLogger -> Hooks
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
clientConnection ClientConfig{..} ver myAuthCIDs peerAuthCIDs =
    newConnection Client params ver myAuthCIDs peerAuthCIDs
  where
    params = confParameters ccConfig

serverConnection :: ServerConfig
                 -> Version -> AuthCIDs -> AuthCIDs
                 -> DebugLogger -> QLogger -> Hooks
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
serverConnection ServerConfig{..} ver myAuthCIDs peerAuthCIDs =
    newConnection Server params ver myAuthCIDs peerAuthCIDs
  where
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

type InputQ  = TQueue Input
type CryptoQ = TQueue Crypto
type OutputQ = TQueue Output
type MigrationQ = TQueue CryptPacket
