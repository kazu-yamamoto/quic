{-# LANGUAGE OverloadedStrings #-}

module Config (
    makeTestServerConfig
  , makeTestServerConfigR
  , testClientConfig
  , testClientConfigR
  , withPipe
  ) where


import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import Network.Socket
import Network.Socket.ByteString
import Network.TLS (Credentials(..), credentialLoadX509)

import Network.QUIC
import Network.QUIC.Internal

makeTestServerConfig :: IO ServerConfig
makeTestServerConfig = do
    cred <- either error id <$> credentialLoadX509 "test/servercert.pem" "test/serverkey.pem"
    let credentials = Credentials [cred]
    return testServerConfig {
        scConfig = (scConfig testServerConfig) {
              confCredentials = credentials
            }
      }

testServerConfig :: ServerConfig
testServerConfig = defaultServerConfig {
    scAddresses = [("127.0.0.1",8003)]
  }

makeTestServerConfigR :: IO ServerConfig
makeTestServerConfigR = do
    cred <- either error id <$> credentialLoadX509 "test/servercert.pem" "test/serverkey.pem"
    let credentials = Credentials [cred]
    return testServerConfigR {
        scConfig = (scConfig testServerConfigR) {
              confCredentials = credentials
            }
      }

testServerConfigR :: ServerConfig
testServerConfigR = defaultServerConfig {
    scAddresses = [("127.0.0.1",8003)]
  , scConfig = (scConfig defaultServerConfig) {
        confQLog = Just "dist"
      }
  }

testClientConfig :: ClientConfig
testClientConfig = defaultClientConfig {
    ccPortName = "8003"
  }

testClientConfigR :: ClientConfig
testClientConfigR = defaultClientConfig {
    ccPortName = "8002"
  , ccDebugLog = True
  , ccConfig = (ccConfig defaultClientConfig) {
        confQLog = Just "dist/test"
      }
  }

withPipe :: IO () -> IO ()
withPipe body = do
    let hints = defaultHints {
            addrSocketType = Datagram
          }
    addrC <- head <$> getAddrInfo (Just hints) (Just "127.0.0.1") (Just "8002")
    let saC = addrAddress addrC
    addrS <- head <$> getAddrInfo (Just hints) (Just "127.0.0.1") (Just "8003")
    let saS = addrAddress addrS
    E.bracket (openSocket addrC) close $ \sockC ->
      E.bracket (openSocket addrS) close $ \sockS -> do
        setSocketOption sockC ReuseAddr 1
        setSocketOption sockS ReuseAddr 1
        bind sockC saC
        connect sockS saS
        tid0 <- forkIO $ forever $ do
            bs <- recv sockS 2048
            dropPacket <- shouldDrop
            unless dropPacket $ void $ send sockC bs
        tid1 <- forkIO $ do
            (bs,saO) <- recvFrom sockC 2048
            connect sockC saO
            void $ send sockS bs
            forever $ do
                bs1 <- recv sockC 2048
                dropPacket <- shouldDrop
                unless dropPacket $ void $ send sockS bs1
        body
        killThread tid0
        killThread tid1
  where
    shouldDrop = do
        w <- getRandomOneByte
        return ((w `mod` 20) == 0)
