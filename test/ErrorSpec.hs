{-# LANGUAGE OverloadedStrings #-}

module ErrorSpec where

import Control.Monad (forever, void)
import Data.ByteString ()
import Network.QUIC
import Network.QUIC.Server
import Test.Hspec
import UnliftIO.Concurrent

import Config
import TransportError

setup :: IO ThreadId
setup = do
    sc' <- makeTestServerConfig
    smgr <- newSessionManager
    let sc = sc' { scSessionManager = smgr
                 , scUse0RTT        = True
                 }
    tid <- forkIO $ run sc loop
    threadDelay 500000 -- give enough time to the server
    return tid
  where
    loop conn = forever $ void $ acceptStream conn

teardown :: ThreadId -> IO ()
teardown tid = killThread tid

spec :: Spec
spec = beforeAll setup $ afterAll teardown $ transportErrorSpec testClientConfig 2000 -- 2 seconds
