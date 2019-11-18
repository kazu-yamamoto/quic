{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection where

import Control.Concurrent
import Control.Concurrent.STM
import Control.Exception as E
import Data.IORef
import Network.TLS (HostName)
import Network.TLS.Extra.Cipher
import Network.TLS.QUIC
import System.Mem.Weak

import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Transport.Error
import Network.QUIC.Transport.Header
import Network.QUIC.Transport.Parameters
import Network.QUIC.Transport.Types

----------------------------------------------------------------

class Config a where
    makeConnection :: a -> IO Connection

instance Config ClientConfig where
    makeConnection = clientConnection

instance Config ServerConfig where
    makeConnection = serverConnection

----------------------------------------------------------------

data ConnectionState = NotOpen | Open | Closing deriving (Eq, Show)

data CloseState = CloseState {
    closeSent     :: Bool
  , closeReceived :: Bool
  } deriving (Eq, Show)

data Role = Client (IORef (Maybe ClientController))
          | Server (IORef (Maybe ServerController))

type GetHandshake = IO ByteString
type PutHandshake = ByteString -> IO ()

data ClientConfig = ClientConfig {
    ccVersion    :: Version
  , ccServerName :: HostName
  , ccPeerCID    :: Maybe CID -- for the test purpose
  , ccMyCID      :: Maybe CID -- for the test purpose
  , ccALPN       :: IO (Maybe [ByteString])
  , ccCiphers    :: [Cipher]
  , ccSend       :: ByteString -> IO ()
  , ccRecv       :: IO ByteString
  , ccParams     :: Parameters
  }

defaultClientConfig :: ClientConfig
defaultClientConfig = ClientConfig {
    ccVersion    = currentDraft
  , ccServerName = "127.0.0.1"
  , ccPeerCID    = Nothing
  , ccMyCID      = Nothing
  , ccALPN       = return Nothing
  , ccCiphers    = ciphersuite_strong
  , ccSend       = \_ -> return ()
  , ccRecv       = return ""
  , ccParams     = defaultParameters
  }

----------------------------------------------------------------

data ServerConfig = ServerConfig {
    scVersion    :: Version
  , scKey        :: FilePath
  , scCert       :: FilePath
  , scSend       :: ByteString -> IO ()
  , scRecv       :: IO ByteString
  , scParams     :: Parameters
  , scClientIni  :: ByteString
  , scALPN       :: Maybe ([ByteString] -> IO ByteString)
  }

defaultServerConfig :: ServerConfig
defaultServerConfig = ServerConfig {
    scVersion    = currentDraft
  , scKey        = "serverkey.pem"
  , scCert       = "servercert.pem"
  , scSend       = \_ -> return ()
  , scRecv       = return ""
  , scParams     = defaultParameters
  , scClientIni  = ""
  , scALPN       = Nothing
  }

----------------------------------------------------------------

data PhaseState = PhaseState {
    receivedPacketNumbers :: [PacketNumber]
  , cryptoOffSet :: Offset
  }

defaultPhaseState :: PhaseState
defaultPhaseState = PhaseState [] 0

----------------------------------------------------------------

data Segment = S StreamID ByteString
             | H PacketType ByteString
             | C PacketType [Frame]
             | E TransportError
             deriving Show

type InputQ  = TQueue Segment
type OutputQ = TQueue Segment

data Connection = Connection {
    role             :: Role
  , myCID            :: CID
  , connSend         :: ByteString -> IO ()
  , connRecv         :: IO ByteString
  , myParams         :: Parameters
  , iniSecrets       :: TrafficSecrets InitialSecret
  , hndSecrets       :: IORef (Maybe (TrafficSecrets HandshakeSecret))
  , appSecrets       :: IORef (Maybe (TrafficSecrets ApplicationSecret))
  , peerParams       :: IORef Parameters
  , peerCID          :: IORef CID
  , usedCipher       :: IORef Cipher
  , negotiatedProto  :: IORef (Maybe ByteString)
  , inputQ           :: InputQ
  , outputQ          :: OutputQ
  -- my packet numbers intentionally using the single space
  , packetNumber     :: IORef PacketNumber
  -- peer's packet numbers
  , initialState     :: IORef PhaseState
  , handshakeState   :: IORef PhaseState
  , applicationState :: IORef PhaseState
  , encryptionLevel  :: TVar EncryptionLevel
  , clientInitial    :: IORef (Maybe ByteString)
  , closeState       :: TVar CloseState -- fixme: stream table
  , connectionState  :: TVar ConnectionState -- fixme: stream table
  , threadIds        :: IORef [Weak ThreadId]
  }

newConnection :: Role -> CID -> CID -> (ByteString -> IO ()) -> IO ByteString -> Parameters -> TrafficSecrets InitialSecret -> IO Connection
newConnection rl mid peercid send recv myparam isecs =
    Connection rl mid send recv myparam isecs
        <$> newIORef Nothing
        <*> newIORef Nothing
        <*> newIORef defaultParameters
        <*> newIORef peercid
        <*> newIORef defaultCipher
        <*> newIORef Nothing
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newIORef 0
        <*> newIORef defaultPhaseState
        <*> newIORef defaultPhaseState
        <*> newIORef defaultPhaseState
        <*> newTVarIO InitialLevel
        <*> newIORef Nothing
        <*> newTVarIO (CloseState False False)
        <*> newTVarIO NotOpen
        <*> newIORef []

clientConnection :: ClientConfig -> IO Connection
clientConnection ClientConfig{..} = do
    let params = encodeParametersList $ diffParameters ccParams
    controller <- clientController ccServerName ccCiphers ccALPN params
    ref <- newIORef $ Just controller
    mycid <- case ccMyCID of
      Nothing  -> newCID
      Just cid -> return cid
    peercid <- case ccPeerCID of
      Nothing  -> newCID
      Just cid -> return cid
    let isecs = initialSecrets ccVersion peercid
    newConnection (Client ref) mycid peercid ccSend ccRecv ccParams isecs

serverConnection :: ServerConfig -> IO Connection
serverConnection ServerConfig{..} = do
    let params = encodeParametersList $ diffParameters scParams
    controller <- serverController scKey scCert scALPN params
    ref <- newIORef $ Just controller
    mcids <- analyzeLongHeaderPacket scClientIni
    case mcids of
      Nothing -> E.throwIO PacketIsBroken
      Just (mycid, peercid) -> do
          let isecs = initialSecrets scVersion mycid
          conn <- newConnection (Server ref) mycid peercid scSend scRecv scParams isecs
          writeIORef (clientInitial conn) (Just scClientIni)
          return conn

----------------------------------------------------------------

setHandshakeSecrets :: Connection -> TrafficSecrets HandshakeSecret -> IO ()
setHandshakeSecrets conn secs = do
    writeIORef (hndSecrets conn) (Just secs)
    atomically $ writeTVar (encryptionLevel conn) HandshakeLevel

setApplicationSecrets :: Connection -> TrafficSecrets ApplicationSecret -> IO ()
setApplicationSecrets conn secs = do
    writeIORef (appSecrets conn) (Just secs)
    atomically $ writeTVar (encryptionLevel conn) RTT1Level

----------------------------------------------------------------

isClient :: Connection -> Bool
isClient conn = case role conn of
                 Client{} -> True
                 Server{} -> False

----------------------------------------------------------------

txInitialSecret :: Connection -> IO Secret
txInitialSecret conn = do
    let (ClientTrafficSecret c, ServerTrafficSecret s) = iniSecrets conn
    return $ Secret $ if isClient conn then c else s

rxInitialSecret :: Connection -> IO Secret
rxInitialSecret conn = do
    let (ClientTrafficSecret c, ServerTrafficSecret s) = iniSecrets conn
    return $ Secret $ if isClient conn then s else c

txHandshakeSecret :: Connection -> IO Secret
txHandshakeSecret conn = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (hndSecrets conn)
    return $ Secret $ if isClient conn then c else s

rxHandshakeSecret :: Connection -> IO Secret
rxHandshakeSecret conn = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (hndSecrets conn)
    return $ Secret $ if isClient conn then s else c

txApplicationSecret :: Connection -> IO Secret
txApplicationSecret conn = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (appSecrets conn)
    return $ Secret $ if isClient conn then c else s

rxApplicationSecret :: Connection -> IO Secret
rxApplicationSecret conn = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (appSecrets conn)
    return $ Secret $ if isClient conn then s else c

----------------------------------------------------------------

getPacketNumber :: Connection -> IO PacketNumber
getPacketNumber conn = atomicModifyIORef' (packetNumber conn) (\pn -> (pn + 1, pn))

----------------------------------------------------------------

addPNs :: Connection -> PacketType -> PacketNumber -> IO ()
addPNs conn pt p = atomicModifyIORef' ref add
  where
    ref = getStateReference conn pt
    add state = (state { receivedPacketNumbers = p : receivedPacketNumbers state}, ())


clearPNs :: Connection -> PacketType -> IO [PacketNumber]
clearPNs conn pt = atomicModifyIORef' ref clear
  where
    ref = getStateReference conn pt
    clear state = (state { receivedPacketNumbers = [] }, receivedPacketNumbers state)

----------------------------------------------------------------

modifyCryptoOffset :: Connection -> PacketType -> Offset -> IO Offset
modifyCryptoOffset conn pt len = atomicModifyIORef' ref modify
  where
    ref = getStateReference conn pt
    modify s = (s { cryptoOffSet = cryptoOffSet s + len}, cryptoOffSet s)

----------------------------------------------------------------

getStateReference :: Connection -> PacketType -> IORef PhaseState
getStateReference conn Initial   = initialState conn
getStateReference conn Handshake = handshakeState conn
getStateReference conn Short     = applicationState conn
getStateReference _   _         = error "getStateReference"

----------------------------------------------------------------

getCipher :: Connection -> IO Cipher
getCipher conn = readIORef (usedCipher conn)

setCipher :: Connection -> Cipher -> IO ()
setCipher conn cipher = writeIORef (usedCipher conn) cipher

setPeerParameters :: Connection -> ParametersList -> IO ()
setPeerParameters Connection{..} plist = do
    def <- readIORef peerParams
    writeIORef peerParams $ updateParameters def plist

setNegotiatedProto :: Connection -> Maybe ByteString -> IO ()
setNegotiatedProto Connection{..} malpn = writeIORef negotiatedProto malpn

clearController :: Connection -> IO ()
clearController conn = case role conn of
  Client ref -> writeIORef ref Nothing
  Server ref -> writeIORef ref Nothing

tlsClientController :: Connection -> IO ClientController
tlsClientController conn = case role conn of
  Client ref -> do
      mc <- readIORef ref
      case mc of
        Nothing         -> return nullController
        Just controller -> return controller
  _ -> return nullController
  where
    nullController _ = return ClientHandshakeDone

tlsServerController :: Connection -> IO ServerController
tlsServerController conn = case role conn of
  Server ref -> do
      mc <- readIORef ref
      case mc of
        Nothing         -> return nullController
        Just controller -> return controller
  _ -> return nullController
  where
    nullController _ = return ServerHandshakeDone

setPeerCID :: Connection -> CID -> IO ()
setPeerCID Connection{..} pcid = writeIORef peerCID pcid

getPeerCID :: Connection -> IO CID
getPeerCID Connection{..} = readIORef peerCID

----------------------------------------------------------------

checkEncryptionLevel :: Connection -> EncryptionLevel -> IO ()
checkEncryptionLevel conn level = atomically $ do
    l <- readTVar $ encryptionLevel conn
    check (l >= level)

readClearClientInitial :: Connection -> IO (Maybe ByteString)
readClearClientInitial Connection{..} = do
    mbs <- readIORef clientInitial
    writeIORef clientInitial Nothing
    return mbs

setCloseSent :: Connection -> IO ()
setCloseSent conn = atomically $ modifyTVar (closeState conn) (\s -> s { closeSent = True })

setCloseReceived :: Connection -> IO ()
setCloseReceived conn = atomically $ modifyTVar (closeState conn) (\s -> s { closeReceived = True })

isCloseSent :: Connection -> IO Bool
isCloseSent conn = atomically (closeSent <$> readTVar (closeState conn))

waitClosed :: Connection -> IO ()
waitClosed conn = atomically $ do
    cs <- readTVar (closeState conn)
    check (cs == CloseState True True)

setConnectionStatus :: Connection -> ConnectionState -> IO ()
setConnectionStatus conn st = atomically (writeTVar (connectionState conn) st)

isConnectionOpen :: Connection -> IO Bool
isConnectionOpen conn = atomically $ do
    st <- readTVar (connectionState conn)
    return $ st == Open

setThreadIds :: Connection -> [ThreadId] -> IO ()
setThreadIds conn tids = do
    wtids <- mapM mkWeakThreadId tids
    writeIORef (threadIds conn) wtids

clearThreads :: Connection -> IO ()
clearThreads conn = do
    wtids <- readIORef (threadIds conn)
    mapM_ kill wtids
    writeIORef (threadIds conn) []
  where
    kill wtid = do
        mtid <- deRefWeak wtid
        case mtid of
          Nothing  -> return ()
          Just tid -> killThread tid
