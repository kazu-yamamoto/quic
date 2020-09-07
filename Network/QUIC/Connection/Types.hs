{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}

module Network.QUIC.Connection.Types where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Crypto.Token as CT
import Data.Array.IO
import Data.X509 (CertificateChain)
import Foreign.Marshal.Alloc (mallocBytes, free)
import Network.Socket (Socket)
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Recovery
import Network.QUIC.Stream
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

data CloseState = CloseState {
    closeSent     :: Bool
  , closeReceived :: Bool
  } deriving (Eq, Show)

----------------------------------------------------------------

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

data Concurrency = Concurrency {
    currentStream :: Int
  , streamType    :: Int
  , maxStreams    :: Int
  }

newConcurrency :: Role -> Direction -> Concurrency
newConcurrency rl dir = Concurrency typ typ 0
 where
   bidi = dir == Bidirectional
   typ | rl == Client = if bidi then 0 else 2
       | otherwise    = if bidi then 1 else 3

----------------------------------------------------------------

-- | A quic connection to carry multiple streams.
data Connection = Connection {
    connState         :: ConnState
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
  , delayedAckCount   :: IORef Int
  , delayedAckCancel  :: IORef (IO ())
  -- State
  , closeState        :: TVar CloseState
  , peerPacketNumber  :: IORef PacketNumber      -- for RTT1
  , streamTable       :: IORef StreamTable
  , myStreamId        :: TVar Concurrency
  , myUniStreamId     :: TVar Concurrency
  , flowTx            :: TVar Flow
  , flowRx            :: IORef Flow
  , migrationState    :: TVar MigrationState
  , minIdleTimeout    :: IORef Microseconds
  , bytesTx           :: TVar Int
  , bytesRx           :: TVar Int
  , addressValidated  :: TVar Bool
  -- TLS
  , pendingQ          :: Array   EncryptionLevel (TVar [CryptPacket])
  , ciphers           :: IOArray EncryptionLevel Cipher
  , coders            :: IOArray EncryptionLevel Coder
  , negotiated        :: IORef Negotiated
  , handshakeCIDs     :: IORef AuthCIDs
  -- Resources
  , connResources     :: IORef (IO ())
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
    getInAntiAmp       = readIORef  . inAntiAmp       . connState

makePendingQ :: IO (Array EncryptionLevel (TVar [CryptPacket]))
makePendingQ = do
    q1 <- newTVarIO []
    q2 <- newTVarIO []
    q3 <- newTVarIO []
    let lst = [(RTT0Level,q1),(HandshakeLevel,q2),(RTT1Level,q3)]
        arr = array (RTT0Level,RTT1Level) lst
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
    outQ <- newTQueueIO
    let put x = atomically $ writeTQueue outQ $ OutRetrans x
    connstate <- newConnState rl
    Connection connstate debugLog qLog hooks (hbuf,hlen) (pbuf,plen)
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
        <*> return outQ
        <*> newTQueueIO
        <*> newShared tvarFlowTx
        <*> newIORef 0
        <*> newIORef (return ())
        -- State
        <*> newTVarIO CloseState { closeSent = False, closeReceived = False }
        <*> newIORef 0
        <*> newIORef emptyStreamTable
        <*> newTVarIO (newConcurrency rl Bidirectional)
        <*> newTVarIO (newConcurrency rl Unidirectional)
        <*> return tvarFlowTx
        <*> newIORef defaultFlow { flowMaxData = initialMaxData myparams }
        <*> newTVarIO NonMigration
        <*> newIORef (milliToMicro $ maxIdleTimeout myparams)
        <*> newTVarIO 0
        <*> newTVarIO 0
        <*> newTVarIO False
        -- TLS
        <*> makePendingQ
        <*> newArray (InitialLevel,RTT1Level) defaultCipher
        <*> newArray (InitialLevel,RTT1Level) initialCoder
        <*> newIORef initialNegotiated
        <*> newIORef peerAuthCIDs
        -- Resources
        <*> newIORef freeBufs
        -- Recovery
        <*> newLDCC connstate qLog put
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
