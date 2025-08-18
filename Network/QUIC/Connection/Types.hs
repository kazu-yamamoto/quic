{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}

module Network.QUIC.Connection.Types where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Crypto.Token as CT
import Data.Array.IO
import Data.ByteString.Internal
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IntMap
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.X509 (CertificateChain)
import Foreign.Marshal.Alloc
import Foreign.Ptr (nullPtr)
import Network.Control (
    Rate,
    RxFlow,
    TxFlow,
    newRate,
    newRxFlow,
    newTxFlow,
 )
import Network.Socket (SockAddr, Socket)
import Network.TLS.QUIC
import System.Mem.Weak (Weak)

import Network.QUIC.Config
import Network.QUIC.Connector
import Network.QUIC.Crypto
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Recovery
import Network.QUIC.Stream
import Network.QUIC.Types

----------------------------------------------------------------

dummySecrets :: TrafficSecrets a
dummySecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

----------------------------------------------------------------

data RoleInfo
    = ClientInfo
        { clientInitialToken :: Token -- new or retry token
        , resumptionInfo :: ResumptionInfo
        , incompatibleVN :: Bool
        , sockConnected :: Bool
        }
    | ServerInfo
        { tokenManager :: ~CT.TokenManager
        , registerCID :: CID -> Connection -> IO ()
        , unregisterCID :: CID -> IO ()
        , askRetry :: Bool
        , stopServer :: IO ()
        , certChain :: Maybe CertificateChain
        }

defaultClientRoleInfo :: RoleInfo
defaultClientRoleInfo =
    ClientInfo
        { clientInitialToken = emptyToken
        , resumptionInfo = defaultResumptionInfo
        , incompatibleVN = False
        , sockConnected = False
        }

defaultServerRoleInfo :: RoleInfo
defaultServerRoleInfo =
    ServerInfo
        { tokenManager = undefined
        , registerCID = \_ _ -> return ()
        , unregisterCID = \_ -> return ()
        , askRetry = False
        , stopServer = return ()
        , certChain = Nothing
        }

-- cidInfoSRT in CIDInfo is only used in client
-- which accepts stateless reset.
data CIDDB = CIDDB
    { usedCIDInfo :: CIDInfo
    , cidInfos :: IntMap CIDInfo
    , revInfos :: Map CID Int
    , nextSeqNum :: Int -- only for mine (new)
    , retirePriorTo :: Int
    , triggeredByMe :: Bool -- only for peer's
    }
    deriving (Show)

newCIDDB :: CID -> CIDDB
newCIDDB cid =
    CIDDB
        { usedCIDInfo = cidInfo
        , cidInfos = IntMap.singleton 0 cidInfo
        , revInfos = Map.singleton cid 0
        , nextSeqNum = 1
        , retirePriorTo = 1
        , triggeredByMe = False
        }
  where
    cidInfo = newCIDInfo 0 cid $ StatelessResetToken ""

----------------------------------------------------------------

data MigrationState
    = NonMigration
    | MigrationStarted
    | SendChallenge PathInfo PathData
    | RecvResponse

{- FOURMOLU_DISABLE -}
instance Eq MigrationState where
    NonMigration     == NonMigration     = True
    MigrationStarted == MigrationStarted = True
    RecvResponse     == RecvResponse     = True
    _                == _                = False
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

data Coder = Coder
    { encrypt :: Buffer -> PlainText -> AssDat -> PacketNumber -> IO Int
    , decrypt :: Buffer -> CipherText -> AssDat -> PacketNumber -> IO Int
    , supplement :: Maybe Supplement
    }

initialCoder :: Coder
initialCoder =
    Coder
        { encrypt = \_ _ _ _ -> return (-1)
        , decrypt = \_ _ _ _ -> return (-1)
        , supplement = Nothing
        }

data Coder1RTT = Coder1RTT
    { coder1RTT :: Coder
    , secretN :: TrafficSecrets ApplicationSecret
    }

initialCoder1RTT :: Coder1RTT
initialCoder1RTT =
    Coder1RTT
        { coder1RTT = initialCoder
        , secretN = (ClientTrafficSecret "", ServerTrafficSecret "")
        }

data Protector = Protector
    { setSample :: Buffer -> IO ()
    , getMask :: IO Buffer
    , unprotect :: Sample -> Mask
    }

initialProtector :: Protector
initialProtector =
    Protector
        { setSample = \_ -> return ()
        , getMask = return nullPtr
        , unprotect = \_ -> Mask ""
        }

----------------------------------------------------------------

data Negotiated = Negotiated
    { tlsHandshakeMode :: HandshakeMode13
    , applicationProtocol :: Maybe NegotiatedProtocol
    , applicationSecretInfo :: ApplicationSecretInfo
    }

initialNegotiated :: Negotiated
initialNegotiated =
    Negotiated
        { tlsHandshakeMode = FullHandshake
        , applicationProtocol = Nothing
        , applicationSecretInfo = ApplicationSecretInfo defaultTrafficSecrets
        }

----------------------------------------------------------------

newtype StreamIdBase = StreamIdBase {fromStreamIdBase :: Int}
    deriving (Eq, Show)

data Concurrency = Concurrency
    { currentStream :: StreamId
    , maxStreams :: StreamIdBase
    }
    deriving (Show)

newConcurrency :: Role -> Direction -> Int -> Concurrency
newConcurrency rl dir n = Concurrency{..}
  where
    bidi = dir == Bidirectional
    currentStream
        | rl == Client = if bidi then 0 else 2
        | otherwise = if bidi then 1 else 3
    maxStreams = StreamIdBase n

----------------------------------------------------------------

type Send = Buffer -> Int -> IO ()
type Recv = IO ReceivedPacket

-- For migration, two SockAddr for the peer are contained.
data PeerInfo = PeerInfo
    { currPathInfo :: PathInfo
    , prevPathInfo :: Maybe PathInfo
    }

data PathInfo = PathInfo
    { peerSockAddr :: SockAddr
    , pathBytesTx :: TVar Int -- TVar for anti amplification
    , pathBytesRx :: TVar Int -- TVar for anti amplification
    , addressValidated :: TVar Bool
    }

newPathInfo :: SockAddr -> IO PathInfo
newPathInfo peerSockAddr = do
    pathBytesTx <- newTVarIO 0
    pathBytesRx <- newTVarIO 0
    addressValidated <- newTVarIO False
    return PathInfo{..}

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
-- | A quic connection to carry multiple streams.
data Connection = Connection
    { connState         :: ConnState
    , -- Actions
      connDebugLog      :: DebugLogger
    -- ^ A logger for debugging.
    , connQLog          :: QLogger
    , connHooks         :: Hooks
    , connSend          :: ~Send -- ~ for testing
    , connRecv          :: ~Recv -- ~ for testing
    -- Manage
    , connRecvQ         :: RecvQ
    , connSocket        :: IORef Socket
    , genStatelessResetToken :: CID -> StatelessResetToken
    , readers           :: IORef (Map Word64 (Weak ThreadId))
    , mainThreadId      :: ThreadId
    , controlRate       :: Rate
    , -- Info
      roleInfo          :: IORef RoleInfo
    , quicVersionInfo   :: IORef VersionInfo
    , origVersionInfo   :: VersionInfo -- chosenVersion is client's ver in Initial
    -- Mine
    , myParameters      :: Parameters
    , myCIDDB           :: IORef CIDDB
    , -- Peer
      peerParameters    :: IORef Parameters
    , peerCIDDB         :: TVar CIDDB
    , peerInfo          :: IORef PeerInfo
    , -- Queues
      inputQ            :: InputQ
    , cryptoQ           :: CryptoQ
    , outputQ           :: OutputQ
    , outputRate        :: Rate
    , shared            :: Shared
    , delayedAckCount   :: IORef Int
    , delayedAckCancel  :: IORef (IO ())
    , -- State
      peerPacketNumber  :: IORef PacketNumber -- for RTT1
    , streamTable       :: IORef StreamTable
    , myStreamId        :: TVar Concurrency -- C:0 S:1
    , myUniStreamId     :: TVar Concurrency -- C:2 S:3
    , peerStreamId      :: IORef Concurrency -- C:1 S:0
    , peerUniStreamId   :: IORef Concurrency -- C:3 S:2
    , flowTx            :: TVar TxFlow
    , flowRx            :: IORef RxFlow
    , migrationState    :: TVar MigrationState
    , sentRetirePriorTo :: IORef Bool
    , minIdleTimeout    :: IORef Microseconds
    , bytesTx           :: IORef Int
    , bytesRx           :: IORef Int
    , -- TLS
      pendingQ          :: Array EncryptionLevel (TVar [ReceivedPacket])
    , ciphers           :: IOArray EncryptionLevel Cipher
    , coders            :: IOArray EncryptionLevel Coder
    , coders1RTT        :: IOArray Bool Coder1RTT
    , protectors        :: IOArray EncryptionLevel Protector
    , currentKeyPhase   :: IORef (Bool, PacketNumber)
    , negotiated        :: IORef Negotiated
    , connMyAuthCIDs    :: IORef AuthCIDs
    , connPeerAuthCIDs  :: IORef AuthCIDs
    , -- Resources
      encodeBuf         :: Buffer
    , encryptRes        :: SizedBuffer
    , decryptBuf        :: Buffer
    , connResources     :: IORef (IO ())
    , -- Recovery
      connLDCC          :: LDCC
    }
{- FOURMOLU_ENABLE -}

instance KeepQlog Connection where
    keepQlog conn = connQLog conn

instance Connector Connection where
    getRole = role . connState
    getEncryptionLevel = readTVarIO . encryptionLevel . connState
    getMaxPacketSize = readIORef . maxPacketSize . connState
    getConnectionState = readTVarIO . connectionState . connState
    getPacketNumber = readIORef . packetNumber . connState
    getAlive = readIORef . connectionAlive . connState

setDead :: Connection -> IO ()
setDead conn = writeIORef (connectionAlive $ connState conn) False

makePendingQ :: IO (Array EncryptionLevel (TVar [ReceivedPacket]))
makePendingQ = do
    q1 <- newTVarIO []
    q2 <- newTVarIO []
    q3 <- newTVarIO []
    let lst = [(RTT0Level, q1), (HandshakeLevel, q2), (RTT1Level, q3)]
        arr = array (RTT0Level, RTT1Level) lst
    return arr

{- FOURMOLU_DISABLE -}
newConnection
    :: Role
    -> Parameters
    -> VersionInfo
    -> AuthCIDs
    -> AuthCIDs
    -> DebugLogger
    -> QLogger
    -> Hooks
    -> IORef Socket
    -> IORef PeerInfo
    -> RecvQ
    -> Send
    -> Recv
    -> (CID -> StatelessResetToken)
    -> IO Connection
newConnection rl myParameters origVersionInfo myAuthCIDs peerAuthCIDs connDebugLog connQLog connHooks connSocket peerInfo connRecvQ ~connSend ~connRecv genStatelessResetToken = do
    connState         <- newConnState rl
    -- Manage
    readers           <- newIORef Map.empty
    mainThreadId      <- myThreadId
    controlRate       <- newRate
    -- Info
    roleInfo          <- newIORef roleinfo
    quicVersionInfo   <- newIORef origVersionInfo
    -- Mine
    myCIDDB           <- newIORef (newCIDDB myCID)
    -- Peer
    peerParameters    <- newIORef baseParameters
    peerCIDDB         <- newTVarIO (newCIDDB peerCID)
    -- Queus
    inputQ            <- newTQueueIO
    cryptoQ           <- newTQueueIO
    outputQ           <- newTQueueIO
    outputRate        <- newRate
    shared            <- newShared
    delayedAckCount   <- newIORef 0
    delayedAckCancel  <- newIORef (return ())
    -- State
    peerPacketNumber  <- newIORef 0
    streamTable       <- newIORef emptyStreamTable
    myStreamId        <- newTVarIO (newConcurrency rl Bidirectional 0)
    myUniStreamId     <- newTVarIO (newConcurrency rl Unidirectional 0)
    peerStreamId      <- newIORef peerConcurrency
    peerUniStreamId   <- newIORef peerUniConcurrency
    flowTx            <- newTVarIO (newTxFlow 0) -- limit is set in Handshake
    flowRx            <- newIORef (newRxFlow $ initialMaxData myParameters)
    migrationState    <- newTVarIO NonMigration
    sentRetirePriorTo <- newIORef False
    minIdleTimeout    <- newIORef (milliToMicro $ maxIdleTimeout myParameters)
    bytesTx           <- newIORef 0
    bytesRx           <- newIORef 0
    -- TLS
    pendingQ          <- makePendingQ
    ciphers           <- newArray (InitialLevel, RTT1Level) defaultCipher
    coders            <- newArray (InitialLevel, HandshakeLevel) initialCoder
    coders1RTT        <- newArray (False, True) initialCoder1RTT
    protectors        <- newArray (InitialLevel, RTT1Level) initialProtector
    currentKeyPhase   <- newIORef (False, 0)
    negotiated        <- newIORef initialNegotiated
    connMyAuthCIDs    <- newIORef myAuthCIDs
    connPeerAuthCIDs  <- newIORef peerAuthCIDs
    -- Resources
    encodeBuf         <- mallocBytes bufsiz -- used sender or closere
    encryptBuf        <- mallocBytes bufsiz
    let encryptRes = SizedBuffer encryptBuf bufsiz -- used sender
    decryptBuf        <- mallocBytes bufsiz -- used receiver
    connResources     <- newIORef (free encodeBuf >> free encryptBuf >> free decryptBuf)
    -- Recovery
    let put x = atomically $ writeTQueue outputQ $ OutRetrans x
    connLDCC          <- newLDCC connState connQLog put
    return Connection{..}
  where
    isclient = rl == Client
    roleinfo
        | isclient = defaultClientRoleInfo
        | otherwise = defaultServerRoleInfo
    myCID = fromJust $ initSrcCID myAuthCIDs
    peerCID = fromJust $ initSrcCID peerAuthCIDs
    peer
        | isclient = Server
        | otherwise = Client
    peerConcurrency = newConcurrency peer Bidirectional (initialMaxStreamsBidi myParameters)
    peerUniConcurrency = newConcurrency peer Unidirectional (initialMaxStreamsUni myParameters)
    bufsiz = maximumUdpPayloadSize
{- FOURMOLU_ENABLE -}

defaultTrafficSecrets :: (ClientTrafficSecret a, ServerTrafficSecret a)
defaultTrafficSecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

----------------------------------------------------------------

clientConnection
    :: ClientConfig
    -> VersionInfo
    -> AuthCIDs
    -> AuthCIDs
    -> DebugLogger
    -> QLogger
    -> Hooks
    -> IORef Socket
    -> IORef PeerInfo
    -> RecvQ
    -> Send
    -> Recv
    -> (CID -> StatelessResetToken)
    -> IO Connection
clientConnection ClientConfig{..} verInfo myAuthCIDs peerAuthCIDs =
    newConnection Client ccParameters verInfo myAuthCIDs peerAuthCIDs

serverConnection
    :: ServerConfig
    -> VersionInfo
    -> AuthCIDs
    -> AuthCIDs
    -> DebugLogger
    -> QLogger
    -> Hooks
    -> IORef Socket
    -> IORef PeerInfo
    -> RecvQ
    -> Send
    -> Recv
    -> (CID -> StatelessResetToken)
    -> IO Connection
serverConnection ServerConfig{..} verInfo myAuthCIDs peerAuthCIDs =
    newConnection Server scParameters verInfo myAuthCIDs peerAuthCIDs

----------------------------------------------------------------

newtype Input = InpStream Stream deriving (Show)
data Crypto = InpHandshake EncryptionLevel ByteString deriving (Show)

data Output
    = OutControl EncryptionLevel [Frame]
    | OutHandshake [(EncryptionLevel, ByteString)]
    | OutRetrans PlainPacket

type InputQ = TQueue Input
type CryptoQ = TQueue Crypto
type OutputQ = TQueue Output

----------------------------------------------------------------

type SendStreamQ = TQueue TxStreamData

data Shared = Shared
    { sharedCloseSent :: IORef Bool
    , sharedCloseReceived :: IORef Bool
    , shared1RTTReady :: IORef Bool
    , sharedSendStreamQ :: SendStreamQ
    }

newShared :: IO Shared
newShared = do
    sharedCloseSent <- newIORef False
    sharedCloseReceived <- newIORef False
    shared1RTTReady <- newIORef False
    sharedSendStreamQ <- newTQueueIO
    return Shared{..}
