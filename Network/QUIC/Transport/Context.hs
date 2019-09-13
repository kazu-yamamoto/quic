{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Transport.Context where

import Crypto.Random (getRandomBytes)
import Data.ByteString (ByteString)
import Data.IORef
-- import Data.ByteString
import qualified Network.TLS as TLS
import qualified Network.TLS.Extra.Cipher as TLS

import Network.QUIC.TLS
import Network.QUIC.Transport.Types

data Role = Client TLS.ClientParams
          | Server TLS.ServerParams

data Context = Context {
    role :: Role
  , tlsConetxt        :: TLS.Context
  , myCID             :: CID
  , initialSecret     :: (Secret, Secret)
  , peerCID           :: IORef CID
  , usedCipher        :: IORef Cipher
  , earlySecret       :: IORef (Maybe (TLS.SecretPair TLS.EarlySecret))
  , handshakeSecret   :: IORef (Maybe (TLS.SecretTriple TLS.HandshakeSecret))
  , applicationSecret :: IORef (Maybe (TLS.SecretTriple TLS.ApplicationSecret))
  -- intentionally using the single space for packet numbers.
  , packetNumber      :: IORef PacketNumber
  }

data ClientConfig = ClientConfig {
    ccVersion    :: Version
  , ccServerName :: TLS.HostName
  , ccPeerCID    :: Maybe CID -- for the test purpose
  , ccMyCID      :: Maybe CID -- for the test purpose
  , ccALPN       :: IO (Maybe [ByteString])
  , ccCiphers    :: [TLS.Cipher]
  }

defaultClientConfig :: ClientConfig
defaultClientConfig = ClientConfig {
    ccVersion    = Draft22
  , ccServerName = "127.0.0.1"
  , ccPeerCID    = Nothing
  , ccMyCID      = Nothing
  , ccALPN       = return Nothing
  , ccCiphers    = TLS.ciphersuite_strong
  }

clientContext :: ClientConfig -> IO Context
clientContext ClientConfig{..} = do
    (tlsctx, cparams) <- tlsClientContext ccServerName ccCiphers ccALPN
    mycid <- case ccMyCID of
      Nothing  -> CID <$> getRandomBytes 8 -- fixme: hard-coding
      Just cid -> return cid
    peercid <- case ccPeerCID of
      Nothing -> CID <$> getRandomBytes 8 -- fixme: hard-coding
      Just cid -> return cid
    let cis = clientInitialSecret ccVersion peercid
        sis = serverInitialSecret ccVersion peercid
    Context (Client cparams) tlsctx mycid (cis, sis) <$> newIORef peercid <*> newIORef defaultCipher <*> newIORef Nothing <*> newIORef Nothing <*> newIORef Nothing <*> newIORef 0

serverContext :: Version -> CID -> FilePath -> FilePath -> IO Context
serverContext ver mycid key cert = do
    (tlsctx, sparams) <- tlsServerContext key cert
    let cis = clientInitialSecret ver mycid
        sis = serverInitialSecret ver mycid
    -- fixme: CID ""
    Context (Server sparams) tlsctx mycid (cis, sis) <$> newIORef (CID "") <*> newIORef defaultCipher <*> newIORef Nothing <*> newIORef Nothing <*> newIORef Nothing <*> newIORef 0

tlsClientParams :: Context -> TLS.ClientParams
tlsClientParams ctx = case role ctx of
  Client cparams -> cparams
  Server _       -> error "tlsClientParams"

tlsServerParams :: Context -> TLS.ServerParams
tlsServerParams ctx = case role ctx of
  Server sparams -> sparams
  Client _       -> error "tlsServerParams"

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
    Just st <- readIORef (handshakeSecret ctx)
    case role ctx of
      Client _ -> let TLS.ClientTrafficSecret s = TLS.triClient st
                  in return $ Secret s
      Server _ -> let TLS.ServerTrafficSecret s = TLS.triServer st
                  in return $ Secret s

rxHandshakeSecret :: Context -> IO Secret
rxHandshakeSecret ctx = do
    Just st <- readIORef (handshakeSecret ctx)
    case role ctx of
      Client _ -> let TLS.ServerTrafficSecret s = TLS.triServer st
                  in return $ Secret s
      Server _ -> let TLS.ClientTrafficSecret s = TLS.triClient st
                  in return $ Secret s

txApplicationSecret :: Context -> IO Secret
txApplicationSecret ctx = do
    Just st <- readIORef (applicationSecret ctx)
    case role ctx of
      Client _ -> let TLS.ClientTrafficSecret s = TLS.triClient st
                  in return $ Secret s
      Server _ -> let TLS.ServerTrafficSecret s = TLS.triServer st
                  in return $ Secret s

rxApplicationSecret :: Context -> IO Secret
rxApplicationSecret ctx = do
    Just st <- readIORef (applicationSecret ctx)
    case role ctx of
      Client _ -> let TLS.ServerTrafficSecret s = TLS.triServer st
                  in return $ Secret s
      Server _ -> let TLS.ClientTrafficSecret s = TLS.triClient st
                  in return $ Secret s
