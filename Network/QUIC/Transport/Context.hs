{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Transport.Context where

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

data PhaseState a = PhaseState {
    receivedPacketNumbers :: [PacketNumber]
  , cryptoOffSet :: Offset
  , secrets :: (Maybe (TrafficSecrets a))
  }

defaultPhaseState :: PhaseState a
defaultPhaseState = PhaseState [] 0 Nothing

----------------------------------------------------------------

data Context = Context {
    role              :: Role
  , myCID             :: CID
  , ctxSend           :: ByteString -> IO ()
  , ctxRecv           :: IO ByteString
  , myParams          :: Parameters
  , peerParams        :: IORef Parameters
  , peerCID           :: IORef CID
  , usedCipher        :: IORef Cipher
  , negotiatedProto   :: IORef (Maybe ByteString)
  -- my packet numbers intentionally using the single space
  , packetNumber      :: IORef PacketNumber
  -- peer's packet numbers
  , initialState      :: IORef (Maybe (PhaseState InitialSecret))
  , handshakeState    :: IORef (Maybe (PhaseState HandshakeSecret))
  , applicationState  :: IORef (Maybe (PhaseState ApplicationSecret))
  }

newContext :: Role -> CID -> CID -> (ByteString -> IO ()) -> IO ByteString -> Parameters -> TrafficSecrets InitialSecret -> IO Context
newContext rl mid peercid send recv myparam isecs =
    Context rl mid send recv myparam
        <$> newIORef defaultParameters
        <*> newIORef peercid
        <*> newIORef defaultCipher
        <*> newIORef Nothing
        <*> newIORef 0
        <*> newIORef (Just defaultPhaseState { secrets = Just isecs } )
        <*> newIORef (Just defaultPhaseState)
        <*> newIORef (Just defaultPhaseState)

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
setHandshakeSecrets ctx secs = modifyIORef (handshakeState ctx) f
  where
    f Nothing  = Nothing
    f (Just s) = Just s { secrets = Just secs }

setApplicationSecrets :: Context -> TrafficSecrets ApplicationSecret -> IO ()
setApplicationSecrets ctx secs = modifyIORef (applicationState ctx) f
  where
    f Nothing  = Nothing
    f (Just s) = Just s { secrets = Just secs }

----------------------------------------------------------------

txInitialSecret :: Context -> IO Secret
txInitialSecret ctx = do
    Just state <- readIORef (initialState ctx)
    let Just (ClientTrafficSecret c, ServerTrafficSecret s) = secrets state
    return $ Secret $ case role ctx of
      Client _ -> c
      Server _ -> s

rxInitialSecret :: Context -> IO Secret
rxInitialSecret ctx = do
    Just state <- readIORef (initialState ctx)
    let Just (ClientTrafficSecret c, ServerTrafficSecret s) = secrets state
    return $ Secret $ case role ctx of
      Client _ -> s
      Server _ -> c

txHandshakeSecret :: Context -> IO Secret
txHandshakeSecret ctx = do
    Just state <- readIORef (handshakeState ctx)
    let Just (ClientTrafficSecret c, ServerTrafficSecret s) = secrets state
    return $ Secret $ case role ctx of
      Client _ -> c
      Server _ -> s

rxHandshakeSecret :: Context -> IO Secret
rxHandshakeSecret ctx = do
    Just state <- readIORef (handshakeState ctx)
    let Just (ClientTrafficSecret c, ServerTrafficSecret s) = secrets state
    return $ Secret $ case role ctx of
      Client _ -> s
      Server _ -> c

txApplicationSecret :: Context -> IO Secret
txApplicationSecret ctx = do
    Just state <- readIORef (applicationState ctx)
    let Just (ClientTrafficSecret c, ServerTrafficSecret s) = secrets state
    return $ Secret $ case role ctx of
      Client _ -> c
      Server _ -> s

rxApplicationSecret :: Context -> IO Secret
rxApplicationSecret ctx = do
    Just state <- readIORef (applicationState ctx)
    let Just (ClientTrafficSecret c, ServerTrafficSecret s) = secrets state
    return $ Secret $ case role ctx of
      Client _ -> s
      Server _ -> c

----------------------------------------------------------------

getPacketNumber :: Context -> IO PacketNumber
getPacketNumber ctx = atomicModifyIORef' (packetNumber ctx) (\pn -> ((pn + 1), pn))

----------------------------------------------------------------

addPNs :: PacketNumber -> Maybe (PhaseState a) -> (Maybe (PhaseState a), ())
addPNs _ Nothing      = (Nothing, ())
addPNs p (Just state) = (Just state { receivedPacketNumbers = p : receivedPacketNumbers state}, ())

clearPNs :: Maybe (PhaseState a) -> (Maybe (PhaseState a), [PacketNumber])
clearPNs Nothing      = (Nothing, [])
clearPNs (Just state) = (Just state { receivedPacketNumbers = [] }, receivedPacketNumbers state)

addInitialPNs :: Context -> PacketNumber -> IO ()
addInitialPNs ctx p =  atomicModifyIORef' (initialState ctx) $ addPNs p

clearInitialPNs :: Context -> IO [PacketNumber]
clearInitialPNs ctx = atomicModifyIORef' (initialState ctx) clearPNs

addHandshakePNs :: Context -> PacketNumber -> IO ()
addHandshakePNs ctx p = atomicModifyIORef' (handshakeState ctx) $ addPNs p

clearHandshakePNs :: Context -> IO [PacketNumber]
clearHandshakePNs ctx = atomicModifyIORef' (handshakeState ctx)  clearPNs

addApplicationPNs :: Context -> PacketNumber -> IO ()
addApplicationPNs ctx p = atomicModifyIORef' (applicationState ctx) $ addPNs p

clearApplicationPNs :: Context -> IO [PacketNumber]
clearApplicationPNs ctx = atomicModifyIORef' (applicationState ctx) clearPNs

----------------------------------------------------------------

modifyCryptoOffset :: Context -> Offset -> IO Offset
modifyCryptoOffset ctx len = atomicModifyIORef' (initialState ctx) modify
  where
    modify Nothing = error "modifyCryptoOffset"
    modify (Just s) =( Just s { cryptoOffSet = cryptoOffSet s + len}, cryptoOffSet s)

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
