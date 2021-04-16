{-# LANGUAGE OverloadedStrings #-}

module Config (
    makeTestServerConfig
  , makeTestServerConfigR
  , testClientConfig
  , testClientConfigR
  , setServerQlog
  , setClientQlog
  , withPipe
  , Scenario(..)
  ) where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import qualified Data.List as L
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
      , scALPN = Just chooseALPN
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
      , scALPN = Just chooseALPN
      }

testServerConfigR :: ServerConfig
testServerConfigR = defaultServerConfig {
    scAddresses = [("127.0.0.1",8003)]
  }

testClientConfig :: ClientConfig
testClientConfig = defaultClientConfig {
    ccPortName = "8003"
  }

testClientConfigR :: ClientConfig
testClientConfigR = defaultClientConfig {
    ccPortName = "8002"
  , ccDebugLog = True
--  , ccConfig = (ccConfig defaultClientConfig) {
--        confQLog = Just "dist/test"
--      }
  }

setServerQlog :: ServerConfig -> ServerConfig
setServerQlog sc = sc
--setServerQlog sc = sc {
--    scConfig = (scConfig sc) {
--        confQLog = Just "dist"
--    }
--}

setClientQlog :: ClientConfig -> ClientConfig
setClientQlog cc = cc
--setClientQlog cc = cc {
--    ccConfig = (ccConfig cc) {
--        confQLog = Just "dist/test"
--    }
--}

data Scenario = Randomly Int
              | DropClientPacket [Int]
              | DropServerPacket [Int]

withPipe :: Scenario -> IO () -> IO ()
withPipe scenario body = do
    addrC <- resolve "8002"
    let saC = addrAddress addrC
    addrS <- resolve "8003"
    let saS = addrAddress addrS
    irefC <- newIORef 0
    irefS <- newIORef 0
    E.bracket (openSocket addrC) close $ \sockC ->
      E.bracket (openSocket addrS) close $ \sockS -> do
        setSocketOption sockC ReuseAddr 1
        setSocketOption sockS ReuseAddr 1
        bind sockC saC
        connect sockS saS
        -- from client
        tid0 <- forkIO $ do
            (bs,saO) <- recvFrom sockC 2048
            connect sockC saO
            n0 <- atomicModifyIORef' irefC $ \x -> (x + 1, x)
            dropPacket0 <- shouldDrop scenario True n0
            unless dropPacket0 $ void $ send sockS bs
            forever $ do
                bs1 <- recv sockC 2048
                n <- atomicModifyIORef' irefC $ \x -> (x + 1, x)
                dropPacket <- shouldDrop scenario True n
                unless dropPacket $ void $ send sockS bs1
        -- to server
        tid1 <- forkIO $ forever $ do
            bs <- recv sockS 2048
            n <- atomicModifyIORef' irefS $ \x -> (x + 1, x)
            dropPacket <- shouldDrop scenario False n
            unless dropPacket $ void $ send sockC bs
        body
        killThread tid0
        killThread tid1
  where
    hints = defaultHints { addrSocketType = Datagram }
    resolve port =
        head <$> getAddrInfo (Just hints) (Just "127.0.0.1") (Just port)
    shouldDrop (Randomly n) _ _ = do
        w <- getRandomOneByte
        return ((w `mod` fromIntegral n) == 0)
    shouldDrop (DropClientPacket ns) isC pn
      | isC       = return (pn `elem` ns)
      | otherwise = return False
    shouldDrop (DropServerPacket ns) isC pn
      | isC       = return False
      | otherwise = return (pn `elem` ns)

chooseALPN :: Version -> [ByteString] -> IO ByteString
chooseALPN ver protos = return $ case mh3idx of
    Nothing    -> case mhqidx of
      Nothing    -> ""
      Just _     -> hqX
    Just h3idx ->  case mhqidx of
      Nothing    -> h3X
      Just hqidx -> if h3idx < hqidx then h3X else hqX
  where
    (h3X, hqX) = makeProtos ver
    mh3idx = h3X `L.elemIndex` protos
    mhqidx = hqX `L.elemIndex` protos

makeProtos :: Version -> (ByteString, ByteString)
makeProtos ver = (h3X,hqX)
  where
    verbs = C8.pack $ show $ fromVersion ver
    h3X = "h3-" `BS.append` verbs
    hqX = "hq-" `BS.append` verbs
