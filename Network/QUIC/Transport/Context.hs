module Network.QUIC.Transport.Context where

import Data.IORef

import Network.QUIC.TLS

data Role = Client | Server deriving (Eq,Show)

data Context = Context {
    role :: Role
  , cipherRef :: IORef Cipher
  }

clientContext :: IO Context
clientContext = Context Client <$> newIORef defaultCipher

serverContext :: IO Context
serverContext = Context Server <$> newIORef defaultCipher

getCipher :: Context -> IO Cipher
getCipher ctx = readIORef (cipherRef ctx)

setCipher :: Context -> Cipher -> IO ()
setCipher ctx cipher = writeIORef (cipherRef ctx) cipher
