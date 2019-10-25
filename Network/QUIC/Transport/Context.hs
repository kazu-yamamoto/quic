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

data Context = Context {
    role              :: Role
  , myCID             :: CID
  , initialSecret     :: (Secret, Secret)
  , ctxSend           :: ByteString -> IO ()
  , ctxRecv           :: IO ByteString
  , myParams          :: Parameters
  , peerParams        :: IORef Parameters
  , peerCID           :: IORef CID
  , usedCipher        :: IORef Cipher
  , handshakeSecret   :: IORef (Maybe (TrafficSecrets HandshakeSecret))
  , applicationSecret :: IORef (Maybe (TrafficSecrets ApplicationSecret))
  -- my packet numbers intentionally using the single space
  , packetNumber      :: IORef PacketNumber
  -- peer's packet numbers
  , initialPNs        :: IORef [PacketNumber]
  , handshakePNs      :: IORef [PacketNumber]
  , applicationPNs    :: IORef [PacketNumber]
  , cryptoOffset      :: IORef Offset
  , negotiatedProto   :: IORef (Maybe ByteString)
  }

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
    let cis = clientInitialSecret ccVersion peercid
        sis = serverInitialSecret ccVersion peercid
    Context (Client controller) mycid (cis, sis) ccSend ccRecv ccParams
        <$> newIORef defaultParameters
        <*> newIORef peercid
        <*> newIORef defaultCipher
        <*> newIORef Nothing
        <*> newIORef Nothing
        <*> newIORef 0
        <*> newIORef []
        <*> newIORef []
        <*> newIORef []
        <*> newIORef 0
        <*> newIORef Nothing

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

serverContext :: ServerConfig -> IO Context
serverContext ServerConfig{..} = do
    controller <- tlsServerController scKey scCert
    let cis = clientInitialSecret scVersion scMyCID
        sis = serverInitialSecret scVersion scMyCID
    Context (Server controller) scMyCID (cis, sis) scSend scRecv scParams
        <$> newIORef defaultParameters
        <*> newIORef (CID "") -- fixme
        <*> newIORef defaultCipher
        <*> newIORef Nothing
        <*> newIORef Nothing
        <*> newIORef 0
        <*> newIORef []
        <*> newIORef []
        <*> newIORef []
        <*> newIORef 0
        <*> newIORef Nothing

getCipher :: Context -> IO Cipher
getCipher ctx = readIORef (usedCipher ctx)

setCipher :: Context -> Cipher -> IO ()
setCipher ctx cipher = writeIORef (usedCipher ctx) cipher

txInitialSecret :: Context -> Secret
txInitialSecret ctx = case role ctx of
    Client _ -> cis
    Server _ -> sis
  where
    (cis, sis) = initialSecret ctx

rxInitialSecret :: Context -> Secret
rxInitialSecret ctx = case role ctx of
    Client _ -> sis
    Server _ -> cis
  where
    (cis, sis) = initialSecret ctx

txHandshakeSecret :: Context -> IO Secret
txHandshakeSecret ctx = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (handshakeSecret ctx)
    return $ Secret $ case role ctx of
      Client _ -> c
      Server _ -> s

rxHandshakeSecret :: Context -> IO Secret
rxHandshakeSecret ctx = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (handshakeSecret ctx)
    return $ Secret $ case role ctx of
      Client _ -> s
      Server _ -> c

txApplicationSecret :: Context -> IO Secret
txApplicationSecret ctx = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (applicationSecret ctx)
    return $ Secret $ case role ctx of
      Client _ -> c
      Server _ -> s

rxApplicationSecret :: Context -> IO Secret
rxApplicationSecret ctx = do
    Just (ClientTrafficSecret c, ServerTrafficSecret s) <- readIORef (applicationSecret ctx)
    return $ Secret $ case role ctx of
      Client _ -> s
      Server _ -> c

getPacketNumber :: Context -> IO PacketNumber
getPacketNumber ctx = atomicModifyIORef' (packetNumber ctx) (\pn -> ((pn + 1), pn))

addInitialPNs :: Context -> PacketNumber -> IO ()
addInitialPNs ctx p = atomicModifyIORef' (initialPNs ctx) (\ps -> (p:ps, ()))

clearInitialPNs :: Context -> IO [PacketNumber]
clearInitialPNs ctx = atomicModifyIORef' (initialPNs ctx) (\ps -> ([], ps))

addHandshakePNs :: Context -> PacketNumber -> IO ()
addHandshakePNs ctx p = atomicModifyIORef' (handshakePNs ctx) (\ps -> (p:ps, ()))

clearHandshakePNs :: Context -> IO [PacketNumber]
clearHandshakePNs ctx = atomicModifyIORef' (handshakePNs ctx) (\ps -> ([], ps))

addApplicationPNs :: Context -> PacketNumber -> IO ()
addApplicationPNs ctx p = atomicModifyIORef' (applicationPNs ctx) (\ps -> (p:ps, ()))

clearApplicationPNs :: Context -> IO [PacketNumber]
clearApplicationPNs ctx = atomicModifyIORef' (applicationPNs ctx) (\ps -> ([], ps))

tlsClientHandshake :: Context -> ClientController
tlsClientHandshake ctx = case role ctx of
  Client controller -> controller
  _ -> error "tlsClientHandshake"

setPeerParameters :: Context -> ParametersList -> IO ()
setPeerParameters Context{..} plist = do
    def <- readIORef peerParams
    writeIORef peerParams $ updateParameters def plist

setNegotiatedProto :: Context -> Maybe ByteString -> IO ()
setNegotiatedProto Context{..} malpn = writeIORef negotiatedProto malpn
