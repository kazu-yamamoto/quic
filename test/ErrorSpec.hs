{-# LANGUAGE OverloadedStrings #-}

module ErrorSpec where

import Control.Concurrent
import Control.Monad (forever, void)
import Data.ByteString ()
import Network.QUIC
import Network.QUIC.Server
import Test.Hspec

import Config
import TransportError

setup :: IO ThreadId
setup = do
    sc' <- makeTestServerConfig
    smgr <- newSessionManager
    let sc =
            sc'
                { scSessionManager = smgr
                , scUse0RTT = True
                }
    tid <- forkIO $ run sc loop
    threadDelay 500000 -- give enough time to the server
    return tid
  where
    -- Answering on what it is given.  A server that only accepts cannot
    -- catch a stream handed to the application before the frame that opened
    -- it was looked over -- the answer is what reaches the peer, for a
    -- stream the peer never opened, and the peer calls that a
    -- STREAM_STATE_ERROR before our FLOW_CONTROL_ERROR arrives.
    loop conn = forever $ do
        strm <- acceptStream conn
        void $ forkIO $ sendStream strm "x"

teardown :: ThreadId -> IO ()
teardown = killThread

spec :: Spec
spec =
    beforeAll setup $ afterAll teardown $ transportErrorSpec testClientConfig 2000 -- 2 seconds
