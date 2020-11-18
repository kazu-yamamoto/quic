{-# LANGUAGE OverloadedStrings #-}

module ErrorSpec where

import Control.Concurrent
import Control.Monad (forever, void)
import Data.ByteString ()
import Network.QUIC
import System.Timeout (timeout)
import Test.Hspec

import Config
import Transport

setup :: IO ()
setup = do
    sc <- makeTestServerConfig
    void $ forkIO $ runQUICServer sc loop
    threadDelay 500000 -- give enough time to the server
  where
    loop conn = forever $ do
        strm <- acceptStream conn
        void $ forkIO $ do
            mbs <- timeout 1000000 $ recvStream strm 1024
            case mbs of
              Just "EXIT" -> stopQUICServer conn
              _           -> return ()
            closeStream conn strm

teardown :: () -> IO ()
teardown _ = do
    let cc = testClientConfig
    runQUICClient cc $ \conn -> do
        strm <- stream conn
        sendStream strm "EXIT"
        closeStream conn strm
        threadDelay 1000000

spec :: Spec
spec = beforeAll setup $ afterAll teardown $ transportSpec testClientConfig
