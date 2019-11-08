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
import Network.QUIC.Transport.Types
import Network.QUIC.Transport.Parameters

data Role = Client ClientController
          | Server ServerController

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
    ccVersion    = Draft23
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
  , scMyCID      :: CID
  , scKey        :: FilePath
  , scCert       :: FilePath
  , scSend       :: ByteString -> IO ()
  , scRecv       :: IO ByteString
  , scParams     :: Parameters
  }

defaultServerConfig :: ServerConfig
defaultServerConfig = ServerConfig {
    scVersion    = Draft23
  , scMyCID      = CID ""
  , scKey        = "serverkey.pem"
  , scCert       = "servercert.pem"
  , scSend       = \_ -> return ()
  , scRecv       = return ""
  , scParams     = defaultParameters
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

clientContext :: ClientConfig -> IO Context
clientContext ClientConfig{..} = do
    let params = encodeParametersList $ diffParameters ccParams
    controller <- tlsClientController ccServerName ccCiphers ccALPN params
    mycid <- case ccMyCID of
      Nothing  -> CID <$> getRandomBytes 8 -- fixme: hard-coding
      Just cid -> return cid
    peercid <- case ccPeerCID of
      Nothing -> CID <$> getRandomBytes 8 -- fixme: hard-coding
      Just cid -> return cid
    let isecs = initialSecrets ccVersion peercid
    newContext (Client controller) mycid peercid ccSend ccRecv ccParams isecs

serverContext :: ServerConfig -> IO Context
serverContext ServerConfig{..} = do
    controller <- tlsServerController scKey scCert
    let isecs = initialSecrets scVersion scMyCID
        peercid = CID "" -- fixme
    newContext (Server controller) scMyCID peercid scSend scRecv scParams isecs

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
                 Client _ -> True
                 Server _ -> False

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

tlsClientHandshake :: Context -> ClientController
tlsClientHandshake ctx = case role ctx of
  Client controller -> controller
  _ -> error "tlsClientHandshake"

setPeerCID :: Context -> CID -> IO ()
setPeerCID Context{..} pcid = writeIORef peerCID pcid

getPeerCID :: Context -> IO CID
getPeerCID Context{..} = readIORef peerCID

----------------------------------------------------------------

checkEncryptionLevel :: Context -> EncryptionLevel -> IO ()
checkEncryptionLevel ctx level = atomically $ do
    l <- readTVar $ encryptionLevel ctx
    check (l >= level)
