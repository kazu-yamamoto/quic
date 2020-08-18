{-# LANGUAGE OverloadedStrings #-}

module IOSpec where

import qualified Data.ByteString as B
import Control.Concurrent
import Control.Concurrent.Async
import Control.Monad
import Network.TLS (Credentials(..), credentialLoadX509)
import Test.Hspec

import Network.QUIC

import Config

spec :: Spec
spec = do
    cred <- runIO $ either error id <$> credentialLoadX509 "test/servercert.pem" "test/serverkey.pem"
    let credentials = Credentials [cred]
        sc0 = testServerConfig {
               scConfig = defaultConfig {
                   confCredentials = credentials
                 }
             }
    describe "send & recv" $ do
        it "can exchange data" $ do
            let cc = testClientConfig
                sc = sc0
            testSendRecv cc sc

testSendRecv :: ClientConfig -> ServerConfig -> IO ()
testSendRecv cc sc = do
    mvar <- newEmptyMVar
    void $ concurrently (client mvar) (server mvar)
  where
    client mvar = runQUICClient cc $ \conn -> do
        strm <- stream conn
        let bs = B.replicate 10000 0
        replicateM_ 1000 $ sendStream strm bs
        shutdownStream strm
        takeMVar mvar
    server mvar = runQUICServer sc $ \conn -> do
        strm <- acceptStream conn
        bs <- recvStream strm 1024
        let len = B.length bs
        n <- loop strm bs len
        n `shouldBe` (10000 * 1000)
        putMVar mvar ()
        stopQUICServer conn
      where
        loop _    "" n = return n
        loop strm _  n = do
            bs <- recvStream strm 1024
            let len = B.length bs
                n' = n + len
            loop strm bs n'
