{-# LANGUAGE OverloadedStrings #-}

module HandshakeSpec where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import Control.Monad
import qualified Data.ByteString as BS
import Data.IORef
import Network.TLS (HandshakeMode13(..), SessionManager(..), SessionData, SessionID, Group(..))
import qualified Network.TLS as TLS
import Test.Hspec

import Network.QUIC

import Config

spec :: Spec
spec = do
    sc0' <- runIO $ makeTestServerConfig
    smgr <- runIO $ newSessionManager
    let sc0 = sc0' { scSessionManager = smgr }
    describe "handshake" $ do
        it "can handshake in the normal case" $ do
            let cc = testClientConfig
                sc = sc0
            testHandshake cc sc FullHandshake
        it "can handshake in the case of TLS hello retry" $ do
            let cc = testClientConfig
                sc = sc0 {
                       scConfig = (scConfig sc0) {
                                    confGroups = [P256]
                                  }
                     }
            testHandshake cc sc HelloRetryRequest
        it "can handshake in the case of QUIC retry" $ do
            let cc = testClientConfig
                sc = sc0 {
                       scRequireRetry = True
                     }
            testHandshake cc sc FullHandshake
        it "can handshake in the case of resumption" $ do
            let cc = testClientConfig
                sc = sc0
            testHandshake2 cc sc (FullHandshake, PreSharedKey) False
        it "can handshake in the case of 0-RTT" $ do
            let cc = testClientConfig
                sc = sc0 {
                       scEarlyDataSize  = 1024
                     }
            testHandshake2 cc sc (FullHandshake, RTT0) True
        it "fails with unknown server certificate" $ do
            let cc1 = testClientConfig {
                        ccValidate = True  -- ouch, default should be reversed
                      }
                cc2 = testClientConfig
                sc  = sc0
                certificateRejected e
                    | HandshakeFailed TLS.CertificateUnknown <- e = True
                    | otherwise = False
            testHandshake3 cc1 cc2 sc certificateRejected
        it "fails with no group in common" $ do
            let cc1 = testClientConfig {
                        ccConfig = (ccConfig testClientConfig) { confGroups = [X25519] }
                      }
                cc2 = testClientConfig {
                        ccConfig = (ccConfig testClientConfig) { confGroups = [P256] }
                      }
                sc  = sc0 {
                        scConfig = (scConfig sc0) {
                              confGroups = [P256]
                            }
                      }
                handshakeFailure e
                    | TransportErrorIsReceived te@(TransportError _) _ <- e = te == cryptoError TLS.HandshakeFailure
                    | otherwise = False
            testHandshake3 cc1 cc2 sc handshakeFailure
        it "can handshake with large EE from a client" $ do
            let cc0 = testClientConfig
                cconf0 = ccConfig cc0
                params = (confParameters cconf0) {
                      greaseParameter = Just (BS.pack (replicate 2400 0))
                    }
                cc = cc0 {
                      ccConfig = cconf0 {
                            confParameters = params
                          }
                    }
                sc = sc0
            testHandshake cc sc FullHandshake
        it "can handshake with large EE from a server (3-times rule)" $ do
            let cc = testClientConfig
                sconf0 = scConfig sc0
                params = (confParameters sconf0) {
                      greaseParameter = Just (BS.pack (replicate 3800 0))
                    }
                sc = sc0 {
                      scConfig = sconf0 {
                            confParameters = params
                          }
                    }
            testHandshake cc sc FullHandshake

onE :: IO b -> IO a -> IO a
onE h b = E.onException b h

testHandshake :: ClientConfig -> ServerConfig -> HandshakeMode13 -> IO ()
testHandshake cc sc mode = void $ concurrently client server
  where
    client = runQUICClient cc $ \conn -> do
        isConnectionOpen conn `shouldReturn` True
        handshakeMode <$> getConnectionInfo conn `shouldReturn` mode
        waitEstablished conn
    server = runQUICServer sc serv
      where
        serv conn = stopQUICServer conn `onE` do
            isConnectionOpen conn `shouldReturn` True
            handshakeMode <$> getConnectionInfo conn `shouldReturn` mode
            waitEstablished conn
            void $ acceptStream conn

testHandshake2 :: ClientConfig -> ServerConfig -> (HandshakeMode13, HandshakeMode13) -> Bool -> IO ()
testHandshake2 cc1 sc (mode1, mode2) use0RTT = void $ concurrently client server
  where
    runClient cc mode = runQUICClient cc $ \conn -> do
        isConnectionOpen conn `shouldReturn` True
        waitEstablished conn
        -- SH/EE is necessary to check 0RTT
        handshakeMode <$> getConnectionInfo conn `shouldReturn` mode
        getResumptionInfo conn
    client = do
        res <- runClient cc1 mode1
        let cc2 = cc1 { ccResumption = res
                      , ccUse0RTT    = use0RTT
                      }
        void $ runClient cc2 mode2
    server = do
        ref <- newIORef (0 :: Int)
        runQUICServer sc $ serv ref
      where
        hndl ref conn = do
            n <- readIORef ref
            if n >= 1 then stopQUICServer conn else writeIORef ref (n + 1)
        serv ref conn = hndl ref conn `onE` do
            isConnectionOpen conn `shouldReturn` True
            waitEstablished conn
            void $ acceptStream conn

testHandshake3 :: ClientConfig -> ClientConfig -> ServerConfig -> (QUICError -> Bool) -> IO ()
testHandshake3 cc1 cc2 sc selector = void $ do
    mvar <- newEmptyMVar
    concurrently (clients mvar) (server mvar)
  where
    clients mvar = do
        let query content conn = do
                isConnectionOpen conn `shouldReturn` True
                waitEstablished conn
                s <- stream conn
                sendStream s content
                shutdownStream s
        runQUICClient cc1 (query "first") `shouldThrow` selector
        runQUICClient cc2 (\conn -> query "second" conn >> takeMVar mvar) `shouldReturn` ()
    server mvar = runQUICServer sc $ \conn -> do
        isConnectionOpen conn `shouldReturn` True
        waitEstablished conn
        s <- acceptStream conn
        recvStream s 1024 `shouldReturn` "second"
        putMVar mvar ()
        stopQUICServer conn

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
