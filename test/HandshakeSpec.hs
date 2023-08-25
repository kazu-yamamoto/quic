{-# LANGUAGE OverloadedStrings #-}

module HandshakeSpec where

import Control.Monad
import qualified Data.ByteString as BS
import Network.TLS (HandshakeMode13(..), Group(..))
import qualified Network.TLS as TLS
import Test.Hspec
import UnliftIO.Concurrent
import qualified UnliftIO.Exception as E

import Network.QUIC
import Network.QUIC.Client as C
import Network.QUIC.Internal hiding (RTT0)
import Network.QUIC.Server as S

import Config

spec :: Spec
spec = do
    sc0' <- runIO makeTestServerConfig
    smgr <- runIO newSessionManager
    var <- runIO newEmptyMVar
    let sc0 = sc0' { scSessionManager = smgr
                   , scHooks = (scHooks sc0') {
                         onServerReady = putMVar var ()
                       }
                   }
    let waitS = takeMVar var :: IO ()
    describe "handshake" $ do
        it "can handshake in the normal case" $ do
            let cc = testClientConfig
                sc = sc0
            testHandshake cc sc waitS FullHandshake
        it "can handshake in the case of TLS hello retry" $ do
            let cc = testClientConfig
                sc = sc0 { scGroups = [P256] }
            testHandshake cc sc waitS HelloRetryRequest
        it "can handshake in the case of QUIC retry" $ do
            let cc = testClientConfig
                sc = sc0 { scRequireRetry = True }
            testHandshake cc sc waitS FullHandshake
        it "can handshake in the case of resumption" $ do
            let cc = testClientConfig
                sc = sc0
            testHandshake2 cc sc waitS (FullHandshake, PreSharedKey) False
        it "can handshake in the case of 0-RTT" $ do
            let cc = testClientConfig
                sc = sc0 { scUse0RTT = True }
            testHandshake2 cc sc waitS (FullHandshake, RTT0) True
        it "fails with unknown server certificate" $ do
            let cc1 = testClientConfig {
                        ccValidate = True  -- ouch, default should be reversed
                      }
                cc2 = testClientConfig
                sc  = sc0
                certificateRejected e
                    | TransportErrorIsSent te@(TransportError _) _ <- e = te == cryptoError TLS.CertificateUnknown
                    | otherwise = False
            testHandshake3 cc1 cc2 sc waitS certificateRejected
        it "fails with no group in common" $ do
            let cc1 = testClientConfig { ccGroups = [X25519] }
                cc2 = testClientConfig { ccGroups = [P256] }
                sc  = sc0 { scGroups = [P256] }
                handshakeFailure e
                    | TransportErrorIsReceived te@(TransportError _) _ <- e = te == cryptoError TLS.HandshakeFailure
                    | otherwise = False
            testHandshake3 cc1 cc2 sc waitS handshakeFailure
        it "can handshake with large HE from a client" $ do
            let cc0 = testClientConfig
                params = (ccParameters cc0) {
                      grease = Just (BS.pack (replicate 2400 0))
                    }
                cc = cc0 { ccParameters = params }
                sc = sc0
            testHandshake cc sc waitS FullHandshake
        it "can handshake with large EE from a server (3-times rule)" $ do
            let cc = testClientConfig
                params = (scParameters sc0) {
                      grease = Just (BS.pack (replicate 3800 0))
                    }
                sc = sc0 { scParameters = params }
            testHandshake cc sc waitS FullHandshake

onE :: IO b -> IO a -> IO a
onE h b = E.onException b h

testHandshake :: ClientConfig -> ServerConfig -> IO () -> HandshakeMode13 -> IO ()
testHandshake cc sc waitS mode = do
    mvar <- newEmptyMVar
    E.bracket (forkIO $ server mvar) killThread $ \_ -> client mvar
  where
    client mvar = do
        waitS
        C.run cc $ \conn -> do
            waitEstablished conn
            handshakeMode <$> getConnectionInfo conn `shouldReturn` mode
            takeMVar mvar
    server mvar = S.run sc $ \conn -> do
        waitEstablished conn
        handshakeMode <$> getConnectionInfo conn `shouldReturn` mode
        putMVar mvar ()

query :: BS.ByteString -> Connection -> IO ()
query content conn = do
    waitEstablished conn
    s <- stream conn
    sendStream s content
    shutdownStream s
    void $ recvStream s 1024

testHandshake2 :: ClientConfig -> ServerConfig -> IO () -> (HandshakeMode13, HandshakeMode13) -> Bool -> IO ()
testHandshake2 cc1 sc waitS (mode1, mode2) use0RTT = do
    mvar <- newEmptyMVar
    E.bracket (forkIO $ server mvar) killThread $ \_ -> client mvar
  where
    runClient cc mode action = C.run cc $ \conn -> do
        void $ action conn
        handshakeMode <$> getConnectionInfo conn `shouldReturn` mode
        threadDelay 50000
        getResumptionInfo conn
    client mvar = do
        waitS
        res <- runClient cc1 mode1 $ query "first"
        threadDelay 50000
        let cc2 = cc1 { ccResumption = res
                      , ccUse0RTT    = use0RTT
                      }
        void $ runClient cc2 mode2 $ query "second"
        takeMVar mvar
    server mvar = S.run sc serv
      where
        serv conn = do
            s <- acceptStream conn
            bs <- recvStream s 1024
            sendStream s "bye"
            closeStream s
            when (bs == "second") $  putMVar mvar ()

testHandshake3 :: ClientConfig -> ClientConfig -> ServerConfig -> IO () -> (QUICException -> Bool) -> IO ()
testHandshake3 cc1 cc2 sc waitS selector = do
    mvar <- newEmptyMVar
    E.bracket (forkIO $ server mvar) killThread $ \_ -> client mvar
  where
    client mvar = do
        waitS
        C.run cc1 (query "first")  `shouldThrow` selector
        C.run cc2 (query "second") `shouldReturn` ()
        takeMVar mvar
    server mvar = S.run sc $ \conn -> do
        s <- acceptStream conn
        recvStream s 1024 `shouldReturn` "second"
        sendStream s "bye"
        closeStream s
        putMVar mvar ()
