module Network.QUIC.Transport.Context where

import Data.IORef
import Data.ByteString
import qualified Network.TLS as TLS

import Network.QUIC.TLS

data Role = Client TLS.ClientParams
          | Server TLS.ServerParams

data Context = Context {
    role :: Role
  , tlsConetxt :: TLS.Context
  , connectionID :: ByteString
  , cipherRef :: IORef Cipher
  }

clientContext :: TLS.HostName -> ByteString -> IO Context
clientContext hostname cid = do
    (tlsctx, cparams) <- tlsClientContext hostname
    ref <- newIORef defaultCipher
    return $ Context (Client cparams) tlsctx cid ref

serverContext :: FilePath -> FilePath -> ByteString -> IO Context
serverContext key cert cid = do
    (tlsctx, sparams) <- tlsServerContext key cert
    ref <- newIORef defaultCipher
    return $ Context (Server sparams) tlsctx cid ref

tlsClientParams :: Context -> TLS.ClientParams
tlsClientParams ctx = case role ctx of
  Client cparams -> cparams
  Server _       -> error "tlsClientParams"

tlsServerParams :: Context -> TLS.ServerParams
tlsServerParams ctx = case role ctx of
  Server sparams -> sparams
  Client _       -> error "tlsServerParams"

getCipher :: Context -> IO Cipher
getCipher ctx = readIORef (cipherRef ctx)

setCipher :: Context -> Cipher -> IO ()
setCipher ctx cipher = writeIORef (cipherRef ctx) cipher
