module Network.QUIC.Transport.Context where

import Data.IORef
import Data.ByteString
import qualified Network.TLS as TLS

import Network.QUIC.TLS
import Network.QUIC.Transport.Types

data Role = Client TLS.ClientParams
          | Server TLS.ServerParams

data Context = Context {
    role :: Role
  , tlsConetxt :: TLS.Context
  , connectionID :: ByteString
  , usedCipher :: IORef Cipher
  , initialSpace :: IORef PacketNumber
  , handshakeSpace :: IORef PacketNumber
  , appDataSpace :: IORef PacketNumber
  }

clientContext :: TLS.HostName -> ByteString -> IO Context
clientContext hostname cid = do
    (tlsctx, cparams) <- tlsClientContext hostname
    ref <- newIORef defaultCipher
    iref <- newIORef 0
    href <- newIORef 0
    aref <- newIORef 0
    return $ Context (Client cparams) tlsctx cid ref iref href aref

serverContext :: FilePath -> FilePath -> ByteString -> IO Context
serverContext key cert cid = do
    (tlsctx, sparams) <- tlsServerContext key cert
    ref <- newIORef defaultCipher
    iref <- newIORef 0
    href <- newIORef 0
    aref <- newIORef 0
    return $ Context (Server sparams) tlsctx cid ref iref href aref

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
