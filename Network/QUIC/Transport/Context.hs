module Network.QUIC.Transport.Context where

import Data.IORef
import Data.ByteString

import Network.QUIC.TLS

data Role = Client | Server deriving (Eq,Show)

data Context = Context {
    role :: Role
  , connectionID :: ByteString
  , cipherRef :: IORef Cipher
  }

clientContext :: ByteString -> IO Context
clientContext cid = Context Client cid <$> newIORef defaultCipher

serverContext :: ByteString -> IO Context
serverContext cid = Context Server cid <$> newIORef defaultCipher

getCipher :: Context -> IO Cipher
getCipher ctx = readIORef (cipherRef ctx)

setCipher :: Context -> Cipher -> IO ()
setCipher ctx cipher = writeIORef (cipherRef ctx) cipher
