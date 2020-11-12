{-# LANGUAGE OverloadedStrings #-}

module ErrorSpec where

import Control.Concurrent
import Data.ByteString ()
import Test.Hspec
import Network.QUIC

import Config
import Transport

setup :: IO (IO ())
setup = do
    sc <- makeTestServerConfig
    var <- newEmptyMVar
    -- To kill this server, one connection must be established
    _ <- forkIO $ runQUICServer sc $ \conn -> do
        waitEstablished conn
        _ <- takeMVar var
        stopQUICServer conn
    threadDelay 50000 -- give time to the server to get ready
    return $ putMVar var ()

teardown :: IO () -> IO ()
teardown action = do
    -- Stop the server
    let ccF = testClientConfig
    runQUICClient ccF $ \conn -> do
        waitEstablished conn
        action

spec :: Spec
spec = beforeAll setup $ afterAll teardown $ transportSpec testClientConfig
