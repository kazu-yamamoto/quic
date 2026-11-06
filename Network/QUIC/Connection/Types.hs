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
import Data.IntSet (IntSet)
import qualified Data.IntSet as IntSet
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.X509 (CertificateChain)
import Foreign.Marshal.Alloc
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
import qualified System.ThreadManager as T

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
    | MigrationAbandoned

{- FOURMOLU_DISABLE -}
instance Eq MigrationState where
    NonMigration     == NonMigration     = True
    MigrationStarted == MigrationStarted = True
    RecvResponse     == RecvResponse     = True
    MigrationAbandoned == MigrationAbandoned = True
    _                == _                = False
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

data Coder = Coder
    { encrypt :: Buffer -> PlainText -> AssDat -> PacketNumber -> IO Int
    , decrypt :: Buffer -> CipherText -> AssDat -> PacketNumber -> IO Int
    }

initialCoder :: Coder
initialCoder =
    Coder
        { encrypt = \_ _ _ _ -> return (-1)
        , decrypt = \_ _ _ _ -> return (-1)
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
    , withMask :: WithMask
    , unprotect :: Sample -> Mask
    }

initialProtector :: Protector
initialProtector =
    Protector
        { setSample = \_ -> return ()
        , withMask = \_ -> return False
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
    , closedStreams :: Int
    -- ^ For the peer's streams: how many of them we are done with
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
    closedStreams = 0

-- | The peer-initiated streams of one type that have been opened so far.
--
-- Every id below 'openedNext' has been opened, save those in
-- 'openedSkipped': the peer used a higher-numbered stream first, which opens
-- these too (RFC 9000 Sec 3.2), but nothing has arrived for them yet.  A
-- stream that has been opened and is no longer in the stream table has been
-- closed, and a frame for it -- typically a retransmission that crossed our
-- acknowledgement -- must not open it again.
data OpenedStreams = OpenedStreams
    { openedNext :: StreamId
    , openedSkipped :: IntSet
    }
    deriving (Show)

newOpenedStreams :: Concurrency -> OpenedStreams
newOpenedStreams conc = OpenedStreams (currentStream conc) IntSet.empty

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
    , pathAbandoned :: TVar Bool
    -- ^ Gone back from: a send waiting for its anti-amplification
    --   credit goes to the path now in use instead.
    }

newPathInfo :: SockAddr -> IO PathInfo
newPathInfo peerSockAddr = do
    pathBytesTx <- newTVarIO 0
    pathBytesRx <- newTVarIO 0
    addressValidated <- newTVarIO False
    pathAbandoned <- newTVarIO False
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
    , connRecvDatagramQ :: DatagramQ
    , connSocket        :: IORef (Socket, TVar Bool)
    -- ^ The socket and the variable which retires its reader: setting it
    --   tells the reader that the socket is not its to read any more.
    --   One reference, so that the two cannot be swapped apart.
    , connRetiredSocks  :: IORef [Socket]
    -- ^ Sockets a reader has left and nobody is in any more.  The sender
    --   closes them, because it is the one thread which could otherwise
    --   be inside a send on one, and the connection's teardown closes
    --   what is left.
    , genStatelessResetToken :: CID -> StatelessResetToken
    , readers           :: T.ThreadManager
    , mainThreadId      :: ThreadId
    , pathAndCIDFrameRate :: Rate
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
    , pathResponseRate  :: Rate
    , queuedControls    :: TVar Int
    -- ^ Control frames in 'outputQ' which the sender has not taken yet.
    , shared            :: Shared
    , delayedAckCount   :: IORef Int
    , delayedAckCancel  :: IORef (IO ())
    , -- State
      peerPacketNumber  :: Array EncryptionLevel (IORef PacketNumber)
    -- ^ The largest the peer has sent, by level.  0-RTT and 1-RTT share
    --   one, as they share a packet number space.
    , streamTable       :: TVar StreamTable
    , -- | What a stream the application has closed still owes the
      -- connection's window, for as long as the peer has not finished it.
      -- See 'Network.QUIC.Connection.StreamTable.departStream'.
      departedStreams   :: TVar (IntMap Departed)
    , myStreamId        :: TVar Concurrency -- C:0 S:1
    , myUniStreamId     :: TVar Concurrency -- C:2 S:3
    , peerStreamId      :: IORef Concurrency -- C:1 S:0
    , peerUniStreamId   :: IORef Concurrency -- C:3 S:2
    , peerOpened        :: IORef OpenedStreams -- C:1 S:0
    , peerUniOpened     :: IORef OpenedStreams -- C:3 S:2
    , flowTx            :: TVar TxFlow
    , flowRx            :: IORef RxFlow
    , migrationState    :: TVar MigrationState
    , sentRetirePriorTo :: IORef Bool
    , minIdleTimeout    :: IORef Microseconds
    , bytesTx           :: IORef Int
    , bytesRx           :: IORef Int
    , connDone          :: TVar Bool
    , connAbortRequest  :: TVar (Maybe (ApplicationProtocolError, ReasonPhrase))
    -- ^ What 'Network.QUIC.Connection.Misc.abortConnection' asked to close
    --   the connection with, for its protocol threads to act on.
    , -- TLS
      pendingQ          :: Array EncryptionLevel (TVar [ReceivedPacket])
    , ciphers           :: IOArray EncryptionLevel Cipher
    , coders            :: IOArray EncryptionLevel Coder
    , coders1RTT        :: IOArray Bool Coder1RTT
    , protectors        :: IOArray EncryptionLevel Protector
    , prevInitialKeys   :: IORef (Maybe (Coder, Protector))
    -- ^ The Initial keys for the version the peer addressed us in, kept
    --   over a compatible version change (RFC 9368)
    , currentKeyPhase   :: IORef (Bool, PacketNumber)
    , negotiated        :: IORef Negotiated
    , connMyAuthCIDs    :: IORef AuthCIDs
    , connPeerAuthCIDs  :: IORef AuthCIDs
    , -- Resources
      encodeBuf         :: Buffer
    , encryptRes        :: SizedBuffer
    , decryptBuf        :: Buffer
    , connResources     :: IORef (IO ())
    , connCloseSent     :: IORef Bool
    -- ^ Whether the peer has been told the connection is over
    , connCloserOwnsSocket :: IORef Bool
    -- ^ Whether the closer has taken the client's socket to close
    , connAuthFailures  :: IORef Int
    -- ^ Packets that have failed authentication, over the whole connection
    , connKeyPackets    :: IORef Int
    -- ^ Packets the 1-RTT key in use has protected
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
    -> IORef (Socket, TVar Bool)
    -> IORef PeerInfo
    -> RecvQ
    -> DatagramQ
    -> Send
    -> Recv
    -> (CID -> StatelessResetToken)
    -> IO Connection
newConnection rl myParameters origVersionInfo myAuthCIDs peerAuthCIDs connDebugLog connQLog connHooks connSocket peerInfo connRecvQ connRecvDatagramQ ~connSend ~connRecv genStatelessResetToken = do
    connState         <- newConnState rl
    -- Manage
    readers           <- T.newThreadManager
    mainThreadId      <- myThreadId
    pathAndCIDFrameRate <- newRate
    -- Info
    roleInfo          <- newIORef roleinfo
    quicVersionInfo   <- newIORef origVersionInfo
    -- Mine
    myCIDDB           <- newIORef (newCIDDB myCID)
    -- Peer
    peerParameters    <- newIORef baseParameters
    peerCIDDB         <- newTVarIO (newCIDDB peerCID)
    -- Queues
    inputQ            <- newTQueueIO
    cryptoQ           <- newTQueueIO
    outputQ           <- newTQueueIO
    pathResponseRate  <- newRate
    queuedControls    <- newTVarIO 0
    shared            <- newShared
    delayedAckCount   <- newIORef 0
    delayedAckCancel  <- newIORef (return ())
    -- State
    peerPacketNumber  <- newPeerPacketNumber
    streamTable       <- newTVarIO emptyStreamTable
    departedStreams   <- newTVarIO IntMap.empty
    myStreamId        <- newTVarIO (newConcurrency rl Bidirectional 0)
    myUniStreamId     <- newTVarIO (newConcurrency rl Unidirectional 0)
    peerStreamId      <- newIORef peerConcurrency
    peerUniStreamId   <- newIORef peerUniConcurrency
    peerOpened        <- newIORef (newOpenedStreams peerConcurrency)
    peerUniOpened     <- newIORef (newOpenedStreams peerUniConcurrency)
    flowTx            <- newTVarIO (newTxFlow 0) -- limit is set in Handshake
    flowRx            <- newIORef (newRxFlow $ initialMaxData myParameters)
    migrationState    <- newTVarIO NonMigration
    sentRetirePriorTo <- newIORef False
    minIdleTimeout    <- newIORef (milliToMicro $ maxIdleTimeout myParameters)
    bytesTx           <- newIORef 0
    bytesRx           <- newIORef 0
    connDone          <- newTVarIO False
    connAbortRequest  <- newTVarIO Nothing
    connRetiredSocks  <- newIORef []
    -- TLS
    pendingQ          <- makePendingQ
    ciphers           <- newArray (InitialLevel, RTT1Level) defaultCipher
    coders            <- newArray (InitialLevel, HandshakeLevel) initialCoder
    coders1RTT        <- newArray (False, True) initialCoder1RTT
    protectors        <- newArray (InitialLevel, RTT1Level) initialProtector
    prevInitialKeys   <- newIORef Nothing
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
    connCloseSent     <- newIORef False
    connCloserOwnsSocket <- newIORef False
    connAuthFailures  <- newIORef 0
    connKeyPackets    <- newIORef 0
    -- Recovery
    -- Counted as 'putOutput' does, which this cannot use.
    let put x = atomically $ do
            let out = OutRetrans x
            writeTQueue outputQ out
            modifyTVar' queuedControls (+ countControls out)
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
    -> IORef (Socket, TVar Bool)
    -> IORef PeerInfo
    -> RecvQ
    -> DatagramQ
    -> Send
    -> Recv
    -> (CID -> StatelessResetToken)
    -> IO Connection
clientConnection ClientConfig{..} verInfo myAuthCIDs peerAuthCIDs =
    newConnection Client ccParameters' verInfo myAuthCIDs peerAuthCIDs
  where
    ccParameters' =
        ccParameters
            { maxDatagramFrameSize = ccMaxDatagramFrameSize
            }

serverConnection
    :: ServerConfig
    -> VersionInfo
    -> AuthCIDs
    -> AuthCIDs
    -> DebugLogger
    -> QLogger
    -> Hooks
    -> IORef (Socket, TVar Bool)
    -> IORef PeerInfo
    -> RecvQ
    -> DatagramQ
    -> Send
    -> Recv
    -> (CID -> StatelessResetToken)
    -> IO Connection
serverConnection ServerConfig{..} verInfo myAuthCIDs peerAuthCIDs =
    newConnection Server scParameters' verInfo myAuthCIDs peerAuthCIDs
  where
    scParameters' =
        scParameters
            { maxDatagramFrameSize = scMaxDatagramFrameSize
            }

----------------------------------------------------------------

newPeerPacketNumber :: IO (Array EncryptionLevel (IORef PacketNumber))
newPeerPacketNumber = do
    ini <- newIORef 0
    app <- newIORef 0
    hnd <- newIORef 0
    return $
        listArray
            (InitialLevel, RTT1Level)
            [ini, app, hnd, app] -- Initial, 0-RTT, Handshake, 1-RTT

----------------------------------------------------------------

newtype Input = InpStream Stream deriving (Show)
data Crypto = InpHandshake EncryptionLevel ByteString deriving (Show)

data Output
    = OutControl EncryptionLevel [Frame]
    | OutHandshake [(EncryptionLevel, ByteString)]
    | OutRetrans PlainPacket
    | -- | 1-RTT frames for a path other than the one in use.
      OutPathProbe PathInfo [Frame]

-- | The control frames of an output, which 'queuedControls' counts.
--   Not data, which flow control bounds, nor what is never resent.
countControls :: Output -> Int
countControls (OutControl _ frames) = length $ filter isControl frames
countControls (OutRetrans (PlainPacket _ plain)) = length $ filter isControl $ plainFrames plain
countControls OutHandshake{} = 0
countControls (OutPathProbe _ frames) = length $ filter isControl frames

isControl :: Frame -> Bool
isControl Padding{} = False
isControl Ack{} = False
isControl StreamF{} = False
isControl CryptoF{} = False
isControl Datagram{} = False
isControl PathResponse{} = False
isControl _ = True

type InputQ = TQueue Input
type CryptoQ = TQueue Crypto
type OutputQ = TQueue Output

----------------------------------------------------------------

type SendStreamQ = TQueue TxStreamData

type DatagramQ = TQueue ByteString

data Shared = Shared
    { sharedCloseSent :: IORef Bool
    , sharedCloseReceived :: TVar (Maybe ReasonPhrase)
    -- ^ The reason of a CONNECTION_CLOSE(NO_ERROR) from the peer
    , shared1RTTReady :: IORef Bool
    , sharedSendStreamQ :: SendStreamQ
    }

newShared :: IO Shared
newShared = do
    sharedCloseSent <- newIORef False
    sharedCloseReceived <- newTVarIO Nothing
    shared1RTTReady <- newIORef False
    sharedSendStreamQ <- newTQueueIO
    return Shared{..}

----------------------------------------------------------------

mainDone :: Connection -> IO ()
mainDone conn = atomically $ writeTVar (connDone conn) True

-- | The peer has closed the connection: we drain, so nothing is sent back
--   (RFC 9000 Sec 10.2.2), and what is waiting on the peer gives up.
setPeerClosed :: Connection -> ReasonPhrase -> IO ()
setPeerClosed conn reason = do
    writeIORef (connCloseSent conn) True
    atomically $ writeTVar (sharedCloseReceived $ shared conn) $ Just reason

isPeerClosed :: Connection -> IO Bool
isPeerClosed conn = isJust <$> readTVarIO (sharedCloseReceived $ shared conn)

-- | Waiting for the peer to close, then throwing 'ConnectionIsClosed'.
--   An alternative for a wait on the peer.
peerClosedSTM :: Connection -> STM a
peerClosedSTM conn = do
    mr <- readTVar $ sharedCloseReceived $ shared conn
    case mr of
        Nothing -> retry
        Just reason -> throwSTM $ ConnectionIsClosed reason

-- | Throwing 'ConnectionIsClosed' if the peer has closed.
checkPeerClosedSTM :: Connection -> STM ()
checkPeerClosedSTM conn = peerClosedSTM conn `orElse` return ()
