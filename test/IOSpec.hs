{-# LANGUAGE OverloadedStrings #-}

module IOSpec where

import qualified Data.ByteString as B
import Control.Concurrent
import Control.Concurrent.Async
import Control.Monad
import Test.Hspec

import Network.QUIC

import Config

spec :: Spec
spec = do
    sc <- runIO $ makeTestServerConfigR
    let cc = testClientConfigR
    describe "send & recv" $ do
        it "can exchange data on random dropping" $ do
            withPipe (Randomly 20) $ testSendRecv cc sc
        it "can exchange data on server 0" $ do
            withPipe (DropServerPacket [0]) $ testSendRecv cc sc
        it "can exchange data on server 1" $ do
            withPipe (DropServerPacket [1]) $ testSendRecv cc sc
        it "can exchange data on server 2" $ do
            withPipe (DropServerPacket [2]) $ testSendRecv cc sc
        it "can exchange data on server 3" $ do
            withPipe (DropServerPacket [3]) $ testSendRecv cc sc
        it "can exchange data on server 4" $ do
            withPipe (DropServerPacket [4]) $ testSendRecv cc sc
        it "can exchange data on server 5" $ do
            withPipe (DropServerPacket [5]) $ testSendRecv cc sc
        it "can exchange data on client 0" $ do
            withPipe (DropClientPacket [0]) $ testSendRecv cc sc
        it "can exchange data on client 1" $ do
            withPipe (DropClientPacket [1]) $ testSendRecv cc sc
--        it "can exchange data on client 2" $ do
--            withPipe (DropClientPacket [2]) $ testSendRecv cc sc
        it "can exchange data on client 3" $ do
            withPipe (DropClientPacket [3]) $ testSendRecv cc sc
        it "can exchange data on client 4" $ do
            withPipe (DropClientPacket [4]) $ testSendRecv cc sc
        it "can exchange data on client 5" $ do
            withPipe (DropClientPacket [5]) $ testSendRecv cc sc

testSendRecv :: ClientConfig -> ServerConfig -> IO ()
testSendRecv cc sc = do
    mvar <- newEmptyMVar
    void $ concurrently (client mvar) (server mvar)
  where
    client mvar = runQUICClient cc $ \conn -> do
        strm <- stream conn
        let bs = B.replicate 10000 0
        replicateM_ 20 $ sendStream strm bs
        shutdownStream strm
        takeMVar mvar
    server mvar = runQUICServer sc $ \conn -> do
        strm <- acceptStream conn
        bs <- recvStream strm 1024
        let len = B.length bs
        n <- loop strm bs len
        n `shouldBe` (10000 * 20)
        putMVar mvar ()
        stopQUICServer conn
      where
        loop _    "" n = return n
        loop strm _  n = do
            bs <- recvStream strm 1024
            let len = B.length bs
                n' = n + len
            loop strm bs n'
