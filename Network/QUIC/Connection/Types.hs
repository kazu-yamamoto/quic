{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}

module Network.QUIC.Connection.Types where

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
import Network.TLS.QUIC
import Network.UDP (UDPSocket)
import UnliftIO.Concurrent
import UnliftIO.STM

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

data RoleInfo = ClientInfo { clientInitialToken :: Token -- new or retry token
                           , resumptionInfo     :: ResumptionInfo
                           , incompatibleVN     :: Bool
                           }
              | ServerInfo { tokenManager    :: ~CT.TokenManager
                           , registerCID     :: CID -> Connection -> IO ()
                           , unregisterCID   :: CID -> IO ()
                           , askRetry        :: Bool
                           , baseThreadId    :: ~ThreadId
                           , certChain       :: Maybe CertificateChain
                           }

defaultClientRoleInfo :: RoleInfo
defaultClientRoleInfo = ClientInfo {
    clientInitialToken = emptyToken
  , resumptionInfo     = defaultResumptionInfo
  , incompatibleVN     = False
  }

defaultServerRoleInfo :: RoleInfo
defaultServerRoleInfo = ServerInfo {
    tokenManager = undefined
  , registerCID = \_ _ -> return ()
  , unregisterCID = \_ -> return ()
  , askRetry = False
  , baseThreadId = undefined
  , certChain = Nothing
  }

-- fixme: limitation
data CIDDB = CIDDB {
    usedCIDInfo   :: CIDInfo
  , cidInfos      :: IntMap CIDInfo
  , revInfos      :: Map CID Int
  , nextSeqNum    :: Int  -- only for mine (new)
  , triggeredByMe :: Bool -- only for peer's
  } deriving (Show)

newCIDDB :: CID -> CIDDB
newCIDDB cid = CIDDB {
    usedCIDInfo   = cidInfo
  , cidInfos      = IntMap.singleton 0 cidInfo
  , revInfos      = Map.singleton cid 0
  , nextSeqNum    = 1
  , triggeredByMe = False
  }
  where
    cidInfo = CIDInfo 0 cid (StatelessResetToken "")

----------------------------------------------------------------

data MigrationState = NonMigration
                    | MigrationStarted
                    | SendChallenge [PathData]
                    | RecvResponse
                    deriving (Eq, Show)

----------------------------------------------------------------

data Coder = Coder {
    encrypt    :: Buffer -> PlainText  -> AssDat -> PacketNumber -> IO Int
  , decrypt    :: Buffer -> CipherText -> AssDat -> PacketNumber -> IO Int
  , supplement :: Maybe Supplement
  }

initialCoder :: Coder
initialCoder = Coder {
    encrypt    = \_ _ _ _ -> return (-1)
  , decrypt    = \_ _ _ _ -> return (-1)
  , supplement = Nothing
  }

data Coder1RTT = Coder1RTT {
    coder1RTT  :: Coder
  , secretN    :: TrafficSecrets ApplicationSecret
  }

initialCoder1RTT :: Coder1RTT
initialCoder1RTT = Coder1RTT {
    coder1RTT  = initialCoder
  , secretN    = (ClientTrafficSecret "", ServerTrafficSecret "")
  }

data Protector = Protector {
    setSample  :: Buffer -> IO ()
  , getMask    :: IO Buffer
  , unprotect :: Sample -> Mask
  }

initialProtector :: Protector
initialProtector = Protector {
    setSample  = \_ -> return ()
  , getMask    = return nullPtr
  , unprotect = \_ -> Mask ""
  }

----------------------------------------------------------------

data Negotiated = Negotiated {
      tlsHandshakeMode :: HandshakeMode13
    , applicationProtocol :: Maybe NegotiatedProtocol
    , applicationSecretInfo :: ApplicationSecretInfo
    }

initialNegotiated :: Negotiated
initialNegotiated = Negotiated {
      tlsHandshakeMode = FullHandshake
    , applicationProtocol = Nothing
    , applicationSecretInfo = ApplicationSecretInfo defaultTrafficSecrets
    }

----------------------------------------------------------------

data Concurrency = Concurrency {
    currentStream :: Int
  , streamType    :: Int
  , maxStreams    :: Int
  }

newConcurrency :: Role -> Direction -> Int -> Concurrency
newConcurrency rl dir n = Concurrency typ typ n
 where
   bidi = dir == Bidirectional
   typ | rl == Client = if bidi then 0 else 2
       | otherwise    = if bidi then 1 else 3

----------------------------------------------------------------

type Send = Buffer -> Int -> IO ()
type Recv = IO ReceivedPacket

----------------------------------------------------------------

-- | A quic connection to carry multiple streams.
data Connection = Connection {
    connState         :: ConnState
  -- Actions
  , connDebugLog      :: DebugLogger -- ^ A logger for debugging.
  , connQLog          :: QLogger
  , connHooks         :: Hooks
  , connSend          :: ~Send -- ~ for testing
  , connRecv          :: ~Recv -- ~ for testing
  -- Manage
  , connRecvQ         :: RecvQ
  , udpSocket         :: ~(IORef UDPSocket)
  , readers           :: IORef (IO ())
  , tmouter           :: IORef (IO ())
  , mainThreadId      :: ThreadId
  -- Info
  , roleInfo          :: IORef RoleInfo
  , quicVersionInfo   :: IORef VersionInfo
  , origVersionInfo   :: VersionInfo -- chosenVersion is client's ver in Initial
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
  , delayedAckCount   :: IORef Int
  , delayedAckCancel  :: IORef (IO ())
  -- State
  , peerPacketNumber  :: IORef PacketNumber      -- for RTT1
  , streamTable       :: IORef StreamTable
  , myStreamId        :: TVar Concurrency
  , myUniStreamId     :: TVar Concurrency
  , peerStreamId      :: IORef Concurrency
  , flowTx            :: TVar Flow
  , flowRx            :: IORef Flow
  , migrationState    :: TVar MigrationState
  , minIdleTimeout    :: IORef Microseconds
  , bytesTx           :: TVar Int
  , bytesRx           :: TVar Int
  , addressValidated  :: TVar Bool
  -- TLS
  , pendingQ          :: Array   EncryptionLevel (TVar [ReceivedPacket])
  , ciphers           :: IOArray EncryptionLevel Cipher
  , coders            :: IOArray EncryptionLevel Coder
  , coders1RTT        :: IOArray Bool            Coder1RTT
  , protectors        :: IOArray EncryptionLevel Protector
  , currentKeyPhase   :: IORef (Bool, PacketNumber)
  , negotiated        :: IORef Negotiated
  , connMyAuthCIDs    :: IORef AuthCIDs
  , connPeerAuthCIDs  :: IORef AuthCIDs
  -- Resources
  , connResources     :: IORef (IO ())
  , encodeBuf         :: Buffer
  , encryptRes        :: SizedBuffer
  , decryptBuf        :: Buffer
  -- Recovery
  , connLDCC          :: LDCC
  }

instance KeepQlog Connection where
    keepQlog conn = connQLog conn

instance Connector Connection where
    getRole            = role . connState
    getEncryptionLevel = readTVarIO . encryptionLevel . connState
    getMaxPacketSize   = readIORef  . maxPacketSize   . connState
    getConnectionState = readTVarIO . connectionState . connState
    getPacketNumber    = readIORef  . packetNumber    . connState
    getAlive           = readIORef  . connectionAlive . connState

setDead :: Connection -> IO ()
setDead conn = writeIORef (connectionAlive $ connState conn) False

makePendingQ :: IO (Array EncryptionLevel (TVar [ReceivedPacket]))
makePendingQ = do
    q1 <- newTVarIO []
    q2 <- newTVarIO []
    q3 <- newTVarIO []
    let lst = [(RTT0Level,q1),(HandshakeLevel,q2),(RTT1Level,q3)]
        arr = array (RTT0Level,RTT1Level) lst
    return arr

newConnection :: Role
              -> Parameters
              -> VersionInfo -> AuthCIDs -> AuthCIDs
              -> DebugLogger -> QLogger -> Hooks
              -> IORef UDPSocket
              -> RecvQ
              -> Send
              -> Recv
              -> IO Connection
newConnection rl myparams verInfo myAuthCIDs peerAuthCIDs debugLog qLog hooks sref recvQ ~send ~recv = do
    outQ <- newTQueueIO
    let put x = atomically $ writeTQueue outQ $ OutRetrans x
    connstate <- newConnState rl
    let bufsiz = maximumUdpPayloadSize
    encBuf   <- mallocBytes bufsiz
    ecrptBuf <- mallocBytes bufsiz
    dcrptBuf <- mallocBytes bufsiz
    Connection connstate debugLog qLog hooks send recv recvQ sref
        <$> newIORef (return ())
        <*> newIORef (return ())
        <*> myThreadId
        -- Info
        <*> newIORef initialRoleInfo
        <*> newIORef verInfo
        <*> return verInfo
        -- Mine
        <*> return myparams
        <*> newIORef (newCIDDB myCID)
        -- Peer
        <*> newIORef baseParameters
        <*> newTVarIO (newCIDDB peerCID)
        -- Queues
        <*> newTQueueIO
        <*> newTQueueIO
        <*> return outQ
        <*> newTQueueIO
        <*> newShared
        <*> newIORef 0
        <*> newIORef (return ())
        -- State
        <*> newIORef 0
        <*> newIORef emptyStreamTable
        <*> newTVarIO (newConcurrency rl Bidirectional  0)
        <*> newTVarIO (newConcurrency rl Unidirectional 0)
        <*> newIORef  peerConcurrency
        <*> newTVarIO defaultFlow
        <*> newIORef defaultFlow { flowMaxData = initialMaxData myparams }
        <*> newTVarIO NonMigration
        <*> newIORef (milliToMicro $ maxIdleTimeout myparams)
        <*> newTVarIO 0
        <*> newTVarIO 0
        <*> newTVarIO False
        -- TLS
        <*> makePendingQ
        <*> newArray (InitialLevel,RTT1Level) defaultCipher
        <*> newArray (InitialLevel,HandshakeLevel) initialCoder
        <*> newArray (False,True) initialCoder1RTT
        <*> newArray (InitialLevel,RTT1Level) initialProtector
        <*> newIORef (False,0)
        <*> newIORef initialNegotiated
        <*> newIORef myAuthCIDs
        <*> newIORef peerAuthCIDs
        -- Resources
        <*> newIORef (free encBuf >> free ecrptBuf >> free dcrptBuf)
        <*> return encBuf   -- used sender or closere
        <*> return (SizedBuffer ecrptBuf bufsiz) -- used sender
        <*> return dcrptBuf -- used receiver
        -- Recovery
        <*> newLDCC connstate qLog put
  where
    isclient = rl == Client
    initialRoleInfo
      | isclient  = defaultClientRoleInfo
      | otherwise = defaultServerRoleInfo
    myCID   = fromJust $ initSrcCID myAuthCIDs
    peerCID = fromJust $ initSrcCID peerAuthCIDs
    peer | isclient  = Server
         | otherwise = Client
    peerConcurrency = newConcurrency peer Bidirectional (initialMaxStreamsBidi myparams)

defaultTrafficSecrets :: (ClientTrafficSecret a, ServerTrafficSecret a)
defaultTrafficSecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

----------------------------------------------------------------

clientConnection :: ClientConfig
                 -> VersionInfo -> AuthCIDs -> AuthCIDs
                 -> DebugLogger -> QLogger -> Hooks
                 -> IORef UDPSocket
                 -> RecvQ -> Send -> Recv
                 -> IO Connection
clientConnection ClientConfig{..} verInfo myAuthCIDs peerAuthCIDs =
    newConnection Client ccParameters verInfo myAuthCIDs peerAuthCIDs

serverConnection :: ServerConfig
                 -> VersionInfo -> AuthCIDs -> AuthCIDs
                 -> DebugLogger -> QLogger -> Hooks
                 -> IORef UDPSocket
                 -> RecvQ -> Send -> Recv
                 -> IO Connection
serverConnection ServerConfig{..} verInfo myAuthCIDs peerAuthCIDs =
    newConnection Server scParameters verInfo myAuthCIDs peerAuthCIDs

----------------------------------------------------------------

newtype Input = InpStream Stream deriving Show
data   Crypto = InpHandshake EncryptionLevel ByteString deriving Show

data Output = OutControl   EncryptionLevel [Frame] (IO ())
            | OutHandshake [(EncryptionLevel,ByteString)]
            | OutRetrans   PlainPacket

type InputQ  = TQueue Input
type CryptoQ = TQueue Crypto
type OutputQ = TQueue Output
type MigrationQ = TQueue ReceivedPacket

----------------------------------------------------------------

type SendStreamQ = TQueue TxStreamData

data Shared = Shared {
    sharedCloseSent     :: IORef Bool
  , sharedCloseReceived :: IORef Bool
  , shared1RTTReady     :: IORef Bool
  , sharedSendStreamQ   :: SendStreamQ
  }

newShared :: IO Shared
newShared = Shared <$> newIORef False
                   <*> newIORef False
                   <*> newIORef False
                   <*> newTQueueIO
