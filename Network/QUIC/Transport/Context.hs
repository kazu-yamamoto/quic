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
  -- intentionally using the single space for packet numbers.
  , packetNumber :: IORef PacketNumber
  }

clientContext :: TLS.HostName -> ByteString -> IO Context
clientContext hostname cid = do
    (tlsctx, cparams) <- tlsClientContext hostname
    Context (Client cparams) tlsctx cid <$> newIORef defaultCipher <*> newIORef 0

serverContext :: FilePath -> FilePath -> ByteString -> IO Context
serverContext key cert cid = do
    (tlsctx, sparams) <- tlsServerContext key cert
    Context (Server sparams) tlsctx cid <$> newIORef defaultCipher <*> newIORef 0

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
