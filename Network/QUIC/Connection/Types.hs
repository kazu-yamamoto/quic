{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}

module Network.QUIC.Connection.Types where

import qualified Data.ByteString as BS
import Control.Concurrent
import Control.Concurrent.STM
import qualified Crypto.Token as CT
import Data.Hourglass
import Data.IORef
import Data.IntMap (IntMap)
import qualified Data.IntMap as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Foreign.Marshal.Alloc (mallocBytes)
import Network.Socket (Socket)
import Network.TLS.QUIC
import System.Mem.Weak

import Network.QUIC.Config
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

data Role = Client | Server deriving (Eq, Show)

----------------------------------------------------------------

data ConnectionState = Handshaking | Established | Closing CloseState deriving (Eq, Show)

data CloseState = CloseState {
    closeSent     :: Bool
  , closeReceived :: Bool
  } deriving (Eq, Show)

----------------------------------------------------------------

type WindowSize = Int

data Stream = Stream {
    streamId         :: StreamId
  , streamConnection :: Connection -- fixme: used for outputQ only
  , streamQ          :: StreamQ
  , streamWindow     :: TVar WindowSize
  , streamStateTx    :: IORef StreamState
  , streamStateRx    :: IORef StreamState
  , streamReass      :: IORef [Reassemble]
  }

instance Show Stream where
    show s = show $ streamId s

newStream :: Connection -> StreamId -> IO Stream
newStream conn sid = Stream sid conn <$> newStreamQ
                                     <*> newTVarIO 65536 -- fixme
                                     <*> newIORef emptyStreamState
                                     <*> newIORef emptyStreamState
                                     <*> newIORef []

data StreamQ = StreamQ {
    streamInputQ :: TQueue ByteString
  , pendingData  :: IORef (Maybe ByteString)
  , finReceived  :: IORef Bool
  }

newStreamQ :: IO StreamQ
newStreamQ = StreamQ <$> newTQueueIO <*> newIORef Nothing <*> newIORef False

putStreamData :: Stream -> ByteString -> IO ()
putStreamData Stream{..} = atomically . writeTQueue (streamInputQ streamQ)

-- See putInputStream
takeStreamData :: Stream -> Int -> IO ByteString
takeStreamData (Stream _ _ StreamQ{..} _ _ _ _) siz0 = do
    fin <- readIORef finReceived
    if fin then
        return ""
      else do
        mb <- readIORef pendingData
        case mb of
          Nothing -> do
              b0 <- atomically $ readTQueue streamInputQ
              if b0 == "" then do
                  writeIORef finReceived True
                  return ""
                else do
                  let len = BS.length b0
                  case len `compare` siz0 of
                      LT -> tryRead (siz0 - len) (b0 :)
                      EQ -> return b0
                      GT -> do
                          let (b1,b2) = BS.splitAt siz0 b0
                          writeIORef pendingData $ Just b2
                          return b1
          Just b0 -> do
              writeIORef pendingData Nothing
              let len = BS.length b0
              tryRead (siz0 - len) (b0 :)
  where
    tryRead siz build = do
        mb <- atomically $ tryReadTQueue streamInputQ
        case mb of
          Nothing -> return $ BS.concat $ build []
          Just b  -> do
              if b == "" then do
                  writeIORef finReceived True
                  return ""
                else do
                  let len = BS.length b
                  case len `compare` siz of
                    LT -> tryRead (siz - len) (build . (b :))
                    EQ -> return $ BS.concat $ build []
                    GT -> do
                        let (b1,b2) = BS.splitAt siz0 b
                        writeIORef pendingData $ Just b2
                        return $ BS.concat $ build [b1]

----------------------------------------------------------------

data StreamState = StreamState {
    streamOffset :: Offset
  , streamFin :: Fin
  } deriving (Eq, Show)

emptyStreamState :: StreamState
emptyStreamState = StreamState 0 False

data Reassemble = Reassemble StreamData Offset Int deriving (Eq, Show)

newtype StreamTable = StreamTable (IntMap Stream)

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

----------------------------------------------------------------

data RoleInfo = ClientInfo { connClientCntrl    :: ClientController
                           , clientInitialToken :: Token -- new or retry token
                           , resumptionInfo     :: ResumptionInfo
                           }
              | ServerInfo { connServerCntrl :: ServerController
                           , tokenManager    :: ~CT.TokenManager
                           , registerCID     :: CID -> Connection -> IO ()
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
  , registerCID = \_ _ -> return ()
  , unregisterCID = \_ -> return ()
  , askRetry = False
  , mainThreadId = undefined
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

data MigrationStatus = SendChallenge [PathData]
                     | RecvResponse
                     | NonMigration
                     deriving (Eq, Show)

----------------------------------------------------------------

-- | A quic connection to carry multiple streams.
data Connection = Connection {
    role              :: Role
  , roleInfo          :: IORef RoleInfo
  , quicVersion       :: IORef Version
  -- Actions
  , connClose         :: Close
  , connDebugLog      :: LogAction
  , connQLog          :: QlogMsg -> IO ()
  -- Manage
  , threadIds         :: IORef [Weak ThreadId]
  , sockInfo          :: IORef (Socket,RecvQ)
  -- Mine
  , myCIDDB           :: IORef CIDDB
  , migrationStatus   :: TVar MigrationStatus
  -- Peer
  , peerCIDDB         :: TVar CIDDB
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
  , myStreamId        :: IORef StreamId
  , myUniStreamId     :: IORef StreamId
  , peerStreamId      :: IORef StreamId
  -- TLS
  , encryptionLevel   :: TVar EncryptionLevel -- to synchronize
  , pendingHandshake  :: TVar [CryptPacket]
  , pendingRTT1       :: TVar [CryptPacket]
  , iniSecrets        :: IORef (TrafficSecrets InitialSecret)
  , elySecInfo        :: IORef EarlySecretInfo
  , hndSecInfo        :: IORef HandshakeSecretInfo
  , appSecInfo        :: IORef ApplicationSecretInfo
  -- WriteBuffer
  , headerBuffer      :: Buffer
  , headerBufferSize  :: BufferSize
  , payloadBuffer     :: Buffer
  , payloadBufferSize :: BufferSize
  -- Misc
  , nextVersion       :: IORef (Maybe Version)
  }

newConnection :: Role -> Version -> CID -> CID
              -> LogAction -> (QlogMsg -> IO ()) -> Close
              -> IORef (Socket,RecvQ)
              -> TrafficSecrets InitialSecret
              -> IO Connection
newConnection rl ver myCID peerCID debugLog qLog close sref isecs =
    Connection rl
        <$> newIORef initialRoleInfo
        <*> newIORef ver
        -- Actions
        <*> return close
        <*> return debugLog
        <*> return qLog
        -- Manage
        <*> newIORef []
        <*> return sref
        -- Mine
        <*> newIORef (newCIDDB myCID)
        <*> newTVarIO NonMigration
        -- Peer
        <*> newTVarIO (newCIDDB peerCID)
        <*> newIORef defaultParameters
        -- Queues
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newIORef []
        -- State
        <*> newTVarIO Handshaking
        <*> newIORef 0
        <*> newIORef (PeerPacketNumbers Set.empty)
        <*> newIORef emptyStreamTable
        <*> newIORef (if isclient then 0 else 1)
        <*> newIORef (if isclient then 2 else 3)
        <*> newIORef (if isclient then 1 else 0)
        -- TLS
        <*> newTVarIO InitialLevel
        <*> newTVarIO []
        <*> newTVarIO []
        <*> newIORef isecs
        <*> newIORef (EarlySecretInfo defaultCipher (ClientTrafficSecret ""))
        <*> newIORef (HandshakeSecretInfo defaultCipher defaultTrafficSecrets)
        <*> newIORef (ApplicationSecretInfo FullHandshake Nothing defaultTrafficSecrets)
        <*> mallocBytes 256
        <*> return 256
        <*> mallocBytes 1280
        <*> return 1280
        <*> newIORef Nothing
  where
    isclient = rl == Client
    initialRoleInfo
      | isclient  = defaultClientRoleInfo
      | otherwise = defaultServerRoleInfo

defaultTrafficSecrets :: (ClientTrafficSecret a, ServerTrafficSecret a)
defaultTrafficSecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

----------------------------------------------------------------

clientConnection :: ClientConfig -> Version -> CID -> CID
                 -> LogAction -> (QlogMsg -> IO ()) -> Close
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
clientConnection ClientConfig{..} ver myCID peerCID debugLog qLog cls sref = do
    let isecs = initialSecrets ver peerCID
    newConnection Client ver myCID peerCID debugLog qLog cls sref isecs

serverConnection :: ServerConfig -> Version -> CID -> CID -> OrigCID
                 -> LogAction -> (QlogMsg -> IO ()) -> Close
                 -> IORef (Socket,RecvQ)
                 -> IO Connection
serverConnection ServerConfig{..} ver myCID peerCID origCID debugLog qLog cls sref = do
    let isecs = case origCID of
          OCFirst oCID -> initialSecrets ver oCID
          OCRetry _    -> initialSecrets ver myCID
    newConnection Server ver myCID peerCID debugLog qLog cls sref isecs

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
           | InpVersion (Maybe Version)
           | InpError QUICError
           deriving Show

data Output = OutStream Stream [StreamData]
            | OutShutdown Stream
            | OutControl EncryptionLevel [Frame]
            | OutEarlyData ByteString
            | OutHandshake [(EncryptionLevel,ByteString)]
            | OutPlainPacket PlainPacket [PacketNumber]
            deriving Show
