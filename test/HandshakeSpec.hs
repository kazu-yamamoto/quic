{-# LANGUAGE OverloadedStrings #-}

module HandshakeSpec where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Monad
import Data.IORef
import Network.TLS
import Test.Hspec

import Network.QUIC
import Network.QUIC.Connection

spec :: Spec
spec = do
    describe "handshake" $ do
        it "can handshake in the normal case" $ do
            let cc = defaultClientConfig
                sc = defaultServerConfig
            testHandshake cc sc FullHandshake
        it "can handshake in the case of TLS hello retry" $ do
            let cc = defaultClientConfig
                sc = defaultServerConfig {
                       scConfig = defaultConfig {
                                    confGroups = [P256]
                                  }
                     }
            testHandshake cc sc HelloRetryRequest
        it "can handshake in the case of QUIC retry" $ do
            let cc = defaultClientConfig
                sc = defaultServerConfig {
                       scRequireRetry = True
                     }
            testHandshake cc sc FullHandshake
        it "can handshake in the case of resumption" $ do
            smgr <- newSessionManager
            let cc = defaultClientConfig
                sc = defaultServerConfig {
                       scSessionManager = smgr
                     }
            testHandshake2 cc sc (FullHandshake, PreSharedKey) False
        it "can handshake in the case of 0-RTT" $ do
            smgr <- newSessionManager
            let cc = defaultClientConfig
                sc = defaultServerConfig {
                       scSessionManager = smgr
                     , scEarlyDataSize  = 1024
                     }
            testHandshake2 cc sc (FullHandshake, RTT0) True

testHandshake :: ClientConfig -> ServerConfig -> HandshakeMode13 -> IO ()
testHandshake cc sc mode = void $ concurrently client server
  where
    sc' = sc {
            scKey  = "test/serverkey.pem"
          , scCert = "test/servercert.pem"
          }
    client = runQUICClient cc $ \conn -> do
        isConnectionOpen conn `shouldReturn` True
        getTLSMode conn `shouldReturn` mode
    server = runQUICServer sc' $ \conn -> do
        isConnectionOpen conn `shouldReturn` True
        threadDelay 100000 -- waiting for CF
        getTLSMode conn `shouldReturn` mode
        stopQUICServer conn

testHandshake2 :: ClientConfig -> ServerConfig -> (HandshakeMode13, HandshakeMode13) -> Bool -> IO ()
testHandshake2 cc1 sc (mode1, mode2) use0RTT = void $ concurrently client server
  where
    sc' = sc {
            scKey  = "test/serverkey.pem"
          , scCert = "test/servercert.pem"
          }
    runClient cc mode = runQUICClient cc $ \conn -> do
        wait1RTTReady conn
        isConnectionOpen conn `shouldReturn` True
        waitEstablished conn
        getTLSMode conn `shouldReturn` mode
        threadDelay 100000 -- waiting for NST
        getResumptionInfo conn
    client = do
        res <- runClient cc1 mode1
        let cc2 = cc1 { ccResumption = res
                      , ccUse0RTT    = use0RTT
                      }
        void $ runClient cc2 mode2
    server = do
        ref <- newIORef (0 :: Int)
        runQUICServer sc' $ \conn -> do
            isConnectionOpen conn `shouldReturn` True
            threadDelay 100000 -- waiting for CF
            n <- readIORef ref
            if n >= 1 then stopQUICServer conn else writeIORef ref (n + 1)

newSessionManager :: IO SessionManager
newSessionManager = sessionManager <$> newIORef Nothing

sessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
sessionManager ref = SessionManager {
    sessionEstablish      = establish
  , sessionResume         = resume
  , sessionResumeOnlyOnce = resume
  , sessionInvalidate     = \_ -> return ()
  }
  where
    establish sid sdata = writeIORef ref $ Just (sid,sdata)
    resume sid = do
        mx <- readIORef ref
        case mx of
          Nothing -> return Nothing
          Just (s,d)
            | s == sid  -> return $ Just d
            | otherwise -> return Nothing
