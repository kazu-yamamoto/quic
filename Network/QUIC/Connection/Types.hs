{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}

module Network.QUIC.Connection.Types where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Crypto.Token as CT
import Data.Array.IO
import Data.IORef
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Set (Set)
import qualified Data.Set as Set
import Data.X509 (CertificateChain)
import Foreign.Marshal.Alloc (mallocBytes, free)
import GHC.Event
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

newtype SentPackets = SentPackets (Seq SentPacket)

emptySentPackets :: SentPackets
emptySentPackets = SentPackets Seq.empty

data SentPacket = SentPacket {
    spPacketNumber :: PacketNumber
  , spLevel        :: EncryptionLevel
  , spPlainPacket  :: PlainPacket
  , spACKs         :: PeerPacketNumbers
  , spTimeSent     :: TimeMillisecond
  , spSentBytes    :: Int
  } deriving Show

data RTT = RTT {
  -- | The most recent RTT measurement made when receiving an ack for
  --   a previously unacked packet.
    latestRTT   :: Milliseconds
  -- | The smoothed RTT of the connection.
  , smoothedRTT :: Milliseconds
  -- | The RTT variation.
  , rttvar      :: Milliseconds
  -- | The minimum RTT seen in the connection, ignoring ack delay.
  , minRTT      :: Milliseconds
  -- | The maximum amount of time by which the receiver intends to
  --   delay acknowledgments for packets in the ApplicationData packet
  --   number space.  The actual ack_delay in a received ACK frame may
  --   be larger due to late timers, reordering, or lost ACK frames.
  , maxAckDelay1RTT :: Milliseconds
  -- | The number of times a PTO has been sent without receiving
  --  an ack.
  , ptoCount :: Int
  }

-- | The RTT used before an RTT sample is taken.
kInitialRTT :: Milliseconds
kInitialRTT = Milliseconds 333

initialRTT :: RTT
initialRTT = RTT {
    latestRTT       = Milliseconds 0
  , smoothedRTT     = kInitialRTT
  , rttvar          = kInitialRTT .>>. 1
  , minRTT          = Milliseconds 0
  , maxAckDelay1RTT = Milliseconds 0
  , ptoCount        = 0
  }

data CC = CC {
  -- | The sum of the size in bytes of all sent packets that contain
  --   at least one ack-eliciting or PADDING frame, and have not been
  --   acked or declared lost.  The size does not include IP or UDP
  --   overhead, but does include the QUIC header and AEAD overhead.
  --   Packets only containing ACK frames do not count towards
  --   bytes_in_flight to ensure congestion control does not impede
  --   congestion feedback.
    bytesInFlight :: Int
  -- | Maximum number of bytes-in-flight that may be sent.
  , congestionWindow :: Int
  -- | The time when QUIC first detects congestion due to loss or ECN,
  --   causing it to enter congestion recovery.  When a packet sent
  --   after this time is acknowledged, QUIC exits congestion
  --   recovery.
  , congestionRecoveryStartTime :: Maybe TimeMillisecond
  -- | Slow start threshold in bytes.  When the congestion window is
  --   below ssthresh, the mode is slow start and the window grows by
  --   the number of bytes acknowledged.
  , ssthresh :: Int
  }

-- | Default limit on the initial bytes in flight.
kInitialWindow :: Int
kInitialWindow = 14720

initialCC :: CC
initialCC = CC {
    bytesInFlight = 0
  , congestionWindow = kInitialWindow
  , congestionRecoveryStartTime = Nothing
  , ssthresh = maxBound
  }

dummySecrets :: TrafficSecrets a
dummySecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

data LossDetection = LossDetection {
    largestAckedPacket           :: Maybe PacketNumber
  , timeOfLastAckElicitingPacket :: Maybe TimeMillisecond
  , lossTime                     :: Maybe TimeMillisecond
  }

initialLossDetection :: LossDetection
initialLossDetection = LossDetection Nothing Nothing Nothing

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
  , encryptionLevel   :: TVar    EncryptionLevel -- to synchronize
  , pendingQ          :: Array   EncryptionLevel (TVar [CryptPacket])
  , ciphers           :: IOArray EncryptionLevel Cipher
  , coders            :: IOArray EncryptionLevel Coder
  , negotiated        :: IORef Negotiated
  , handshakeCIDs     :: IORef AuthCIDs
  -- Resources
  , connResources     :: IORef (IO ())
  -- Recovery
  , recoveryRTT       :: IORef RTT
  , recoveryCC        :: TVar CC
  , sentPackets       :: Array EncryptionLevel (IORef SentPackets)
  , lossDetection     :: Array EncryptionLevel (IORef LossDetection)
  , timeoutKey        :: IORef (Maybe TimeoutKey)
  }

makePendingQ :: IO (Array EncryptionLevel (TVar [CryptPacket]))
makePendingQ = do
    q1 <- newTVarIO []
    q2 <- newTVarIO []
    q3 <- newTVarIO []
    let lst = [(RTT0Level,q1),(HandshakeLevel,q2),(RTT1Level,q3)]
        arr = array (RTT0Level,RTT1Level) lst
    return arr

makeSentPackets :: IO (Array EncryptionLevel (IORef SentPackets))
makeSentPackets = do
    i1 <- newIORef emptySentPackets
    i2 <- newIORef emptySentPackets
    i3 <- newIORef emptySentPackets
    let lst = [(InitialLevel,i1),(HandshakeLevel,i2),(RTT1Level,i3)]
        arr = array (InitialLevel,RTT1Level) lst
    return arr

makeLossDetection :: IO (Array EncryptionLevel (IORef LossDetection))
makeLossDetection = do
    i1 <- newIORef initialLossDetection
    i2 <- newIORef initialLossDetection
    i3 <- newIORef initialLossDetection
    let lst = [(InitialLevel,i1),(HandshakeLevel,i2),(RTT1Level,i3)]
        arr = array (InitialLevel,RTT1Level) lst
    return arr

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
        <*> makePendingQ
        <*> newArray (InitialLevel,RTT1Level) defaultCipher
        <*> newArray (InitialLevel,RTT1Level) initialCoder
        <*> newIORef initialNegotiated
        <*> newIORef peerAuthCIDs
        -- Resources
        <*> newIORef freeBufs
        -- Recovery
        <*> newIORef initialRTT
        <*> newTVarIO initialCC
        <*> makeSentPackets
        <*> makeLossDetection
        <*> newIORef Nothing
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
