{-# LANGUAGE OverloadedStrings #-}

module HandshakeSpec where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import Control.Monad
import qualified Data.ByteString as BS
import Network.TLS (HandshakeMode13(..), Group(..))
import qualified Network.TLS as TLS
import Test.Hspec

import Network.QUIC

import Config

spec :: Spec
spec = do
    sc0' <- runIO makeTestServerConfig
    smgr <- runIO newSessionManager
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
                    | TransportErrorIsSent te@(TransportError _) _ <- e = te == cryptoError TLS.CertificateUnknown
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
testHandshake cc sc mode = void $ concurrently server client
  where
    client = do
        threadDelay 10000
        runQUICClient cc $ \conn -> do
            isConnectionOpen conn `shouldReturn` True
            waitEstablished conn
            handshakeMode <$> getConnectionInfo conn `shouldReturn` mode
    server = runQUICServer sc $ \conn -> do
        isConnectionOpen conn `shouldReturn` True
        waitEstablished conn
        handshakeMode <$> getConnectionInfo conn `shouldReturn` mode
        stopQUICServer conn

query :: BS.ByteString -> Connection -> IO ()
query content conn = do
    waitEstablished conn
    s <- stream conn
    sendStream s content
    shutdownStream s
    void $ recvStream s 1024

testHandshake2 :: ClientConfig -> ServerConfig -> (HandshakeMode13, HandshakeMode13) -> Bool -> IO ()
testHandshake2 cc1 sc (mode1, mode2) use0RTT = void $ concurrently server client
  where
    runClient cc mode action = runQUICClient cc $ \conn -> do
        void $ action conn
        handshakeMode <$> getConnectionInfo conn `shouldReturn` mode
        getResumptionInfo conn
    client = do
        threadDelay 10000
        res <- runClient cc1 mode1 $ query "first"
        threadDelay 10000
        let cc2 = cc1 { ccResumption = res
                      , ccUse0RTT    = use0RTT
                      }
        void $ runClient cc2 mode2 $ query "second"
    server = runQUICServer sc serv
      where
        serv conn = do
            s <- acceptStream conn
            bs <- recvStream s 1024
            sendStream s "bye"
            when (bs == "second") $ stopQUICServer conn

testHandshake3 :: ClientConfig -> ClientConfig -> ServerConfig -> (QUICException -> Bool) -> IO ()
testHandshake3 cc1 cc2 sc selector = void $ concurrently server client
  where
    client = do
        threadDelay 10000
        runQUICClient cc1 (query "first")  `shouldThrow` selector
        runQUICClient cc2 (query "second") `shouldReturn` ()
    server = runQUICServer sc $ \conn -> do
        s <- acceptStream conn
        recvStream s 1024 `shouldReturn` "second"
        sendStream s "bye"
        stopQUICServer conn
