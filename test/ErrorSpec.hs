{-# LANGUAGE OverloadedStrings #-}

module ErrorSpec where

import Control.Concurrent
import Control.Monad (forever, void)
import Data.ByteString ()
import Network.QUIC
import Test.Hspec

import Config
import TransportError

setup :: IO ThreadId
setup = do
    sc <- makeTestServerConfig
    tid <- forkIO $ runQUICServer sc loop
    threadDelay 500000 -- give enough time to the server
    return tid
  where
    loop conn = forever $ void $ acceptStream conn

teardown :: ThreadId -> IO ()
teardown tid = killThread tid

spec :: Spec
spec = beforeAll setup $ afterAll teardown $ transportErrorSpec testClientConfig
