{-# LANGUAGE OverloadedStrings #-}

module IOSpec where

import Control.Concurrent
import Control.Monad
import qualified Data.ByteString as BS
import Test.Hspec
import UnliftIO.Async

import Network.QUIC.Client
import Network.QUIC.Server

import Config

spec :: Spec
spec = do
    sc <- runIO makeTestServerConfigR
    let cc = testClientConfigR
    describe "send & recv" $ do
        it "can exchange data on random dropping" $ do
            withPipe (Randomly 20) $ testSendRecv cc sc 1000
        it "can exchange data on server 0" $ do
            withPipe (DropServerPacket [0]) $ testSendRecv cc sc 20
        it "can exchange data on server 1" $ do
            withPipe (DropServerPacket [1]) $ testSendRecv cc sc 20
        it "can exchange data on server 2" $ do
            withPipe (DropServerPacket [2]) $ testSendRecv cc sc 20
        it "can exchange data on server 3" $ do
            withPipe (DropServerPacket [3]) $ testSendRecv cc sc 20
        it "can exchange data on server 4" $ do
            withPipe (DropServerPacket [4]) $ testSendRecv cc sc 20
        it "can exchange data on server 5" $ do
            withPipe (DropServerPacket [5]) $ testSendRecv cc sc 20
        it "can exchange data on server 6" $ do
            withPipe (DropServerPacket [6]) $ testSendRecv cc sc 20
        it "can exchange data on server 7" $ do
            withPipe (DropServerPacket [7]) $ testSendRecv cc sc 20
        it "can exchange data on server 8" $ do
            withPipe (DropServerPacket [8]) $ testSendRecv cc sc 20
        it "can exchange data on server 9" $ do
            withPipe (DropServerPacket [9]) $ testSendRecv cc sc 20
        it "can exchange data on server 10" $ do
            withPipe (DropServerPacket [10]) $ testSendRecv cc sc 20
        it "can exchange data on server 11" $ do
            withPipe (DropServerPacket [11]) $ testSendRecv cc sc 20
        it "can exchange data on client 0" $ do
            withPipe (DropClientPacket [0]) $ testSendRecv cc sc 20
        it "can exchange data on client 1" $ do
            withPipe (DropClientPacket [1]) $ testSendRecv cc sc 20
        it "can exchange data on client 2" $ do
            withPipe (DropClientPacket [2]) $ testSendRecv cc sc 20
        it "can exchange data on client 3" $ do
            withPipe (DropClientPacket [3]) $ testSendRecv cc sc 20
        it "can exchange data on client 4" $ do
            withPipe (DropClientPacket [4]) $ testSendRecv cc sc 20
        it "can exchange data on client 5" $ do
            withPipe (DropClientPacket [5]) $ testSendRecv cc sc 20
        it "can exchange data on client 6" $ do
            withPipe (DropClientPacket [6]) $ testSendRecv cc sc 20
        it "can exchange data on client 7" $ do
            withPipe (DropClientPacket [7]) $ testSendRecv cc sc 20
        it "can exchange data on client 8" $ do
            withPipe (DropClientPacket [8]) $ testSendRecv cc sc 20
        it "can exchange data on client 9" $ do
            withPipe (DropClientPacket [9]) $ testSendRecv cc sc 20
        it "can exchange data on client 10" $ do
            withPipe (DropClientPacket [10]) $ testSendRecv cc sc 20
        it "can exchange data on client 11" $ do
            withPipe (DropClientPacket [11]) $ testSendRecv cc sc 20

testSendRecv :: ClientConfig -> ServerConfig -> Int -> IO ()
testSendRecv cc sc times = do
    mvar <- newEmptyMVar
    void $ concurrently (client mvar) (server mvar)
  where
    client mvar = do
        threadDelay 10000
        runQUICClient cc $ \conn -> do
            strm <- stream conn
            let bs = BS.replicate 10000 0
            replicateM_ times $ sendStream strm bs
            shutdownStream strm
            takeMVar mvar `shouldReturn` ()
    server mvar = runQUICServer sc $ \conn -> do
        strm <- acceptStream conn
        bs <- recvStream strm 1024
        let len = BS.length bs
        n <- loop strm bs len
        n `shouldBe` (10000 * times)
        putMVar mvar ()
        stopQUICServer conn
      where
        loop _    "" n = return n
        loop strm _  n = do
            bs <- recvStream strm 1024
            let len = BS.length bs
                n' = n + len
            loop strm bs n'
