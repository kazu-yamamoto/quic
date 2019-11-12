{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Context where

import Control.Concurrent.STM
import Crypto.Random (getRandomBytes)
import Data.IORef
import Network.TLS (HostName)
import Network.TLS.Extra.Cipher
import Network.TLS.QUIC

import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Transport.Header
import Network.QUIC.Transport.Parameters
import Network.QUIC.Transport.Types

data ControllerState a = ControllerMaker (IO a)
                       | ControllerRunning a
                       | ControllerDone

data Role = Client (IORef (ControllerState ClientController))
          | Server (IORef (ControllerState ServerController))

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
             deriving Show

type InputQ  = TQueue Segment
type OutputQ = TQueue Segment

data Context = Context {
    role             :: Role
  , myCID            :: CID
  , ctxSend          :: ByteString -> IO ()
  , ctxRecv          :: IO ByteString
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
  }

newContext :: Role -> CID -> CID -> (ByteString -> IO ()) -> IO ByteString -> Parameters -> TrafficSecrets InitialSecret -> IO Context
newContext rl mid peercid send recv myparam isecs =
    Context rl mid send recv myparam isecs
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

clientContext :: ClientConfig -> IO Context
clientContext ClientConfig{..} = do
    let params = encodeParametersList $ diffParameters ccParams
    maker <- clientControllerMaker ccServerName ccCiphers ccALPN params
    ref <- newIORef (ControllerMaker maker)
    mycid <- case ccMyCID of
      Nothing  -> CID <$> getRandomBytes 8 -- fixme: hard-coding
      Just cid -> return cid
    peercid <- case ccPeerCID of
      Nothing  -> CID <$> getRandomBytes 8 -- fixme: hard-coding
      Just cid -> return cid
    let isecs = initialSecrets ccVersion peercid
    newContext (Client ref) mycid peercid ccSend ccRecv ccParams isecs

serverContext :: ServerConfig -> IO (Maybe Context)
serverContext ServerConfig{..} = do
    let params = encodeParametersList $ diffParameters scParams
    maker <- serverControllerMaker scKey scCert scALPN params
    ref <- newIORef (ControllerMaker maker)
    mcids <- analyzeLongHeaderPacket scClientIni
    case mcids of
      Nothing -> return Nothing
      Just (mycid, peercid) -> do
          let isecs = initialSecrets scVersion mycid
          ctx <- newContext (Server ref) mycid peercid scSend scRecv scParams isecs
          writeIORef (clientInitial ctx) (Just scClientIni)
          return $ Just ctx

----------------------------------------------------------------

setHandshakeSecrets :: Context -> TrafficSecrets HandshakeSecret -> IO ()
setHandshakeSecrets ctx secs = do
    writeIORef (hndSecrets ctx) (Just secs)
    atomically $ writeTVar (encryptionLevel ctx) HandshakeLevel

setApplicationSecrets :: Context -> TrafficSecrets ApplicationSecret -> IO ()
setApplicationSecrets ctx secs = do
    writeIORef (appSecrets ctx) (Just secs)
    atomically $ writeTVar (encryptionLevel ctx) ApplicationLevel

----------------------------------------------------------------

isClient :: Context -> Bool
isClient ctx = case role ctx of
                 Client{} -> True
                 Server{} -> False

----------------------------------------------------------------

txInitialSecret :: Context -> IO Secret
txInitialSecret ctx = do
    let (ClientTrafficSecret c, ServerTrafficSecret s) = iniSecrets ctx
    return $ Secret $ if isClient ctx then c else s

rxInitialSecret :: Context -> IO Secret
rxInitialSecret ctx = do
    let (ClientTrafficSecret c, ServerTrafficSecret s) = iniSecrets ctx
    return $ Secret $ if isClient ctx then s else c

txHandshakeSecret :: Context -> IO Secret
txHandshakeSecret ctx = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (hndSecrets ctx)
    return $ Secret $ if isClient ctx then c else s

rxHandshakeSecret :: Context -> IO Secret
rxHandshakeSecret ctx = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (hndSecrets ctx)
    return $ Secret $ if isClient ctx then s else c

txApplicationSecret :: Context -> IO Secret
txApplicationSecret ctx = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (appSecrets ctx)
    return $ Secret $ if isClient ctx then c else s

rxApplicationSecret :: Context -> IO Secret
rxApplicationSecret ctx = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (appSecrets ctx)
    return $ Secret $ if isClient ctx then s else c

----------------------------------------------------------------

getPacketNumber :: Context -> IO PacketNumber
getPacketNumber ctx = atomicModifyIORef' (packetNumber ctx) (\pn -> ((pn + 1), pn))

----------------------------------------------------------------

addPNs :: Context -> PacketType -> PacketNumber -> IO ()
addPNs ctx pt p = atomicModifyIORef' ref add
  where
    ref = getStateReference ctx pt
    add state = (state { receivedPacketNumbers = p : receivedPacketNumbers state}, ())


clearPNs :: Context -> PacketType -> IO [PacketNumber]
clearPNs ctx pt = atomicModifyIORef' ref clear
  where
    ref = getStateReference ctx pt
    clear state = (state { receivedPacketNumbers = [] }, receivedPacketNumbers state)

----------------------------------------------------------------

modifyCryptoOffset :: Context -> PacketType -> Offset -> IO Offset
modifyCryptoOffset ctx pt len = atomicModifyIORef' ref modify
  where
    ref = getStateReference ctx pt
    modify s = (s { cryptoOffSet = cryptoOffSet s + len}, cryptoOffSet s)

----------------------------------------------------------------

getStateReference :: Context -> PacketType -> IORef PhaseState
getStateReference ctx Initial   = initialState ctx
getStateReference ctx Handshake = handshakeState ctx
getStateReference ctx Short     = applicationState ctx
getStateReference _   _         = error "getStateReference"

----------------------------------------------------------------

getCipher :: Context -> IO Cipher
getCipher ctx = readIORef (usedCipher ctx)

setCipher :: Context -> Cipher -> IO ()
setCipher ctx cipher = writeIORef (usedCipher ctx) cipher

setPeerParameters :: Context -> ParametersList -> IO ()
setPeerParameters Context{..} plist = do
    def <- readIORef peerParams
    writeIORef peerParams $ updateParameters def plist

setNegotiatedProto :: Context -> Maybe ByteString -> IO ()
setNegotiatedProto Context{..} malpn = writeIORef negotiatedProto malpn

tlsClientController :: Context -> IO ClientController
tlsClientController ctx = case role ctx of
  Client ref -> do
      mc <- readIORef ref
      case mc of
        ControllerMaker maker -> do
            controller <- maker
            writeIORef ref $ ControllerRunning controller
            return controller
        ControllerRunning controller -> return controller
        ControllerDone -> return $ \_ -> return ClientHandshakeDone
  _ -> error "tlsClientController"

tlsServerController :: Context -> IO ServerController
tlsServerController ctx = case role ctx of
  Server ref -> do
      mc <- readIORef ref
      case mc of
        ControllerMaker maker -> do
            controller <- maker
            writeIORef ref $ ControllerRunning controller
            return controller
        ControllerRunning controller -> return controller
        ControllerDone -> return $ \_ -> return ServerHandshakeDone
  _ -> error "tlsServerController"

setPeerCID :: Context -> CID -> IO ()
setPeerCID Context{..} pcid = writeIORef peerCID pcid

getPeerCID :: Context -> IO CID
getPeerCID Context{..} = readIORef peerCID

----------------------------------------------------------------

checkEncryptionLevel :: Context -> EncryptionLevel -> IO ()
checkEncryptionLevel ctx level = atomically $ do
    l <- readTVar $ encryptionLevel ctx
    check (l >= level)

readClearClientInitial :: Context -> IO (Maybe ByteString)
readClearClientInitial Context{..} = do
    mbs <- readIORef clientInitial
    writeIORef clientInitial Nothing
    return mbs
