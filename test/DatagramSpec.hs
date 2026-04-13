{-# LANGUAGE OverloadedStrings #-}

module DatagramSpec where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString ()
import qualified Data.ByteString as BS
import Test.Hspec

import Network.QUIC
import Network.QUIC.Client as C
import Network.QUIC.Internal hiding (RTT0)
import Network.QUIC.Server as S
import Network.TLS (HandshakeMode13 (..))

import Config

spec :: Spec
spec = do
    sc0' <- runIO makeTestServerConfig
    let sc0 = sc0'
    describe "Datagram MUST requirements" $ do
        -- "An endpoint that receives a DATAGRAM frame when it has not indicated support via the transport parameter MUST terminate the connection with an error of type PROTOCOL_VIOLATION."
        it "Server MUST send PROTOCOL_VIOLATION if DATAGRAM received without negotiation" $ do
            let cc = testClientConfig { ccHooks = (ccHooks testClientConfig) { onPlainCreated = injectDatagram1RTT } }
            testServerExpectError cc sc0 isProtocolViolationReceived

        -- "An endpoint that receives a DATAGRAM frame when it has not indicated support via the transport parameter MUST terminate the connection with an error of type PROTOCOL_VIOLATION."
        it "Client MUST send PROTOCOL_VIOLATION if DATAGRAM received without negotiation" $ do
            let sc = sc0 { scHooks = (scHooks sc0) { onPlainCreated = injectDatagram1RTT } }
            testClientExpectError testClientConfig sc isProtocolViolationSent

        -- "Similarly, an endpoint that receives a DATAGRAM frame that is larger than the value it sent in its max_datagram_frame_size transport parameter MUST terminate the connection with an error of type PROTOCOL_VIOLATION."
        it "Rejects DATAGRAM larger than max_datagram_frame_size" $ do
            let scDtgm = sc0 { scMaxDatagramFrameSize = 10 }
                ccDtgm = testClientConfig { ccMaxDatagramFrameSize = 10
                                          , ccHooks = (ccHooks testClientConfig) { onPlainCreated = injectLargeDatagram } }
            testServerExpectError ccDtgm scDtgm isProtocolViolationReceived

        -- "Like STREAM frames, DATAGRAM frames contain application data and MUST be protected with either 0-RTT or 1-RTT keys."
        it "MUST send PROTOCOL_VIOLATION if DATAGRAM in Initial or Handshake" $ do
            let scDtgm = sc0 { scMaxDatagramFrameSize = 1024 }
                ccDtgm = testClientConfig { ccMaxDatagramFrameSize = 1024
                                          , ccHooks = (ccHooks testClientConfig) { onPlainCreated = injectDatagramInitial } }
            testServerExpectError ccDtgm scDtgm isProtocolViolationReceived

        -- "If a client stores the value of the max_datagram_frame_size transport parameter with their 0-RTT state, they MUST validate that the new value of the max_datagram_frame_size transport parameter sent by the server in the handshake is greater than or equal to the stored value; if not, the client MUST terminate the connection with error PROTOCOL_VIOLATION."
        it "Client MUST reject 0-RTT downgrade server parameters" $ do
            let scInit = sc0 { scMaxDatagramFrameSize = 1024 }
                scDowngrade = sc0 { scMaxDatagramFrameSize = 500 }
                cc0RTT = testClientConfig { ccMaxDatagramFrameSize = 1024 }
            testDatagram0RTTDowngrade cc0RTT scInit scDowngrade

        -- "An endpoint MUST NOT send DATAGRAM frames until it has received the max_datagram_frame_size transport parameter with a non-zero value"
        it "Endpoint MUST NOT send DATAGRAM if not negotiated" $ do
            let scDtgm = sc0 { scMaxDatagramFrameSize = 0 }
                ccDtgm = testClientConfig { ccMaxDatagramFrameSize = 0 }
            mvar <- newEmptyMVar
            smgr <- newSessionManager
            let sc' = scDtgm { scSessionManager = smgr
                             , scHooks = (scHooks scDtgm) { onServerReady = putMVar mvar () } }
            E.bracket (forkIO $ E.handle (\(E.SomeException _) -> return ()) $ S.run sc' (\conn -> waitEstablished conn >> threadDelay 2000000)) killThread $ \_ -> do
                takeMVar mvar
                let isNoSupport (ConnectionIsClosed err) = err == "DATAGRAM not supported by peer"
                    isNoSupport _ = False
                C.run ccDtgm (\conn -> do
                    waitEstablished conn
                    sendDatagram conn "data") `shouldThrow` isNoSupport

        -- "An endpoint MUST NOT send DATAGRAM frames that are larger than the max_datagram_frame_size value it has received from its peer."
        it "Endpoint MUST NOT send DATAGRAM larger than peer's max_datagram_frame_size" $ do
            let scDtgm = sc0 { scMaxDatagramFrameSize = 10 }
                ccDtgm = testClientConfig { ccMaxDatagramFrameSize = 10 }
            mvar <- newEmptyMVar
            smgr <- newSessionManager
            let sc' = scDtgm { scSessionManager = smgr
                             , scHooks = (scHooks scDtgm) { onServerReady = putMVar mvar () } }
            E.bracket (forkIO $ E.handle (\(E.SomeException _) -> return ()) $ S.run sc' (\conn -> waitEstablished conn >> threadDelay 2000000)) killThread $ \_ -> do
                takeMVar mvar
                let isSizeViolation (ConnectionIsClosed err) = err == "DATAGRAM size violation"
                    isSizeViolation _ = False
                C.run ccDtgm (\conn -> do
                    waitEstablished conn
                    sendDatagram conn (BS.replicate 20 0x41)) `shouldThrow` isSizeViolation

        -- "When servers decide to accept 0-RTT data, they MUST send a max_datagram_frame_size transport parameter greater than or equal to the value they sent to the client..."
        it "Server MUST NOT downgrade max_datagram_frame_size on 0-RTT" $ do
            let scInit = sc0 { scMaxDatagramFrameSize = 1024 }
                scDowngrade = sc0 { scMaxDatagramFrameSize = 500 }
                cc0RTT = testClientConfig { ccMaxDatagramFrameSize = 1024 }

            mvar <- newEmptyMVar
            smgr <- newSessionManager

            -- Phase 1
            let scInit' = scInit { scSessionManager = smgr, scUse0RTT = True, scHooks = (scHooks scInit) { onServerReady = putMVar mvar () } }
            res <- E.bracket (forkIO $ S.run scInit' (\c -> waitEstablished c >> threadDelay 100000)) killThread $ \_ -> do
                takeMVar mvar
                C.run cc0RTT $ \conn -> do
                    waitEstablished conn
                    threadDelay 50000
                    getResumptionInfo conn

            -- Phase 2
            let cc2 = cc0RTT { ccResumption = res, ccUse0RTT = True }
            mvar2 <- newEmptyMVar
            let scDowngrade' = scDowngrade { scSessionManager = smgr, scUse0RTT = True, scHooks = (scHooks scDowngrade) { onServerReady = putMVar mvar2 () } }

            E.bracket (forkIO $ E.handle (\(E.SomeException _) -> return ()) $ S.run scDowngrade' (\conn -> do
                        waitEstablished conn
                        threadDelay 2000000)) killThread $ \_ -> do
                takeMVar mvar2
                C.run cc2 (\_ -> threadDelay 2000000) `shouldThrow` isWrongDatagramSize

        -- "The sender MUST either delay sending the frame until the controller allows it or drop the frame without sending it"
        it "Sender MUST apply congestion control to DATAGRAM frames" $ do
            let scDtgm = sc0 { scMaxDatagramFrameSize = 1024 }
                ccDtgm = testClientConfig { ccMaxDatagramFrameSize = 1024 }
            mvar <- newEmptyMVar
            smgr <- newSessionManager
            let sc' = scDtgm { scSessionManager = smgr
                             , scHooks = (scHooks scDtgm) { onServerReady = putMVar mvar () } }
            E.bracket (forkIO $ E.handle (\(E.SomeException _) -> return ()) $ S.run sc' (\conn -> waitEstablished conn >> threadDelay 2000000)) killThread $ \_ -> do
                takeMVar mvar
                C.run ccDtgm $ \conn -> do
                    waitEstablished conn
                    replicateM_ 100 $ do
                        sendDatagram conn (BS.replicate 50 0x41)
                        threadDelay 500

    describe "Datagram SHOULD requirements" $ do
        -- "This frame SHOULD be sent as soon as possible... and MAY be coalesced with other frames."
        it "Can send and receive DATAGRAM in 1-RTT" $ do
            let scDtgm = sc0 { scMaxDatagramFrameSize = 1024 }
                ccDtgm = testClientConfig { ccMaxDatagramFrameSize = 1024 }
            testDatagram1RTT ccDtgm scDtgm True

        -- Zero-length datagrams are explicitly permitted by the spec (Section 4)
        it "Can handle zero-length DATAGRAM" $ do
            let scDtgm = sc0 { scMaxDatagramFrameSize = 1024 }
                ccDtgm = testClientConfig { ccMaxDatagramFrameSize = 1024
                                          , ccHooks = (ccHooks testClientConfig) { onPlainCreated = injectZeroLengthDatagram } }
            testDatagram1RTT ccDtgm scDtgm False

        -- "When clients use 0-RTT, they MAY store the value of the server's max_datagram_frame_size transport parameter. Doing so allows the client to send DATAGRAM frames in 0-RTT packets."
        it "Can utilize 0-RTT DATAGRAM successfully" $ do
            let scDtgm = sc0 { scMaxDatagramFrameSize = 1024 }
                ccDtgm = testClientConfig { ccMaxDatagramFrameSize = 1024 }
            testDatagram0RTT ccDtgm scDtgm

injectDatagram1RTT :: EncryptionLevel -> Plain -> Plain
injectDatagram1RTT lvl plain
    | lvl == RTT1Level = plain { plainFrames = Datagram False "hello" : plainFrames plain }
    | otherwise = plain

injectLargeDatagram :: EncryptionLevel -> Plain -> Plain
injectLargeDatagram lvl plain
    | lvl == RTT1Level = plain { plainFrames = Datagram False (BS.replicate 20 0x41) : plainFrames plain }
    | otherwise = plain

injectDatagramInitial :: EncryptionLevel -> Plain -> Plain
injectDatagramInitial lvl plain
    | lvl == InitialLevel = plain { plainFrames = Datagram False "hello" : plainFrames plain }
    | otherwise = plain

injectZeroLengthDatagram :: EncryptionLevel -> Plain -> Plain
injectZeroLengthDatagram lvl plain
    | lvl == RTT1Level = plain { plainFrames = Datagram False "" : plainFrames plain }
    | otherwise = plain

isProtocolViolationSent :: QUICException -> Bool
isProtocolViolationSent (TransportErrorIsSent ProtocolViolation _) = True
isProtocolViolationSent _ = False

isProtocolViolationReceived :: QUICException -> Bool
isProtocolViolationReceived (TransportErrorIsReceived ProtocolViolation _) = True
isProtocolViolationReceived _ = False

isWrongDatagramSize :: QUICException -> Bool
isWrongDatagramSize (TransportErrorIsSent ProtocolViolation _) = True
isWrongDatagramSize (TransportErrorIsReceived ProtocolViolation _) = True
isWrongDatagramSize _ = False

-- | Server detects the error and sends ConnectionClose; client receives it.
testServerExpectError :: ClientConfig -> ServerConfig -> (QUICException -> Bool) -> IO ()
testServerExpectError cc sc selector = do
    mvar <- newEmptyMVar
    smgr <- newSessionManager
    let sc' = sc { scSessionManager = smgr
                 , scHooks = (scHooks sc) { onServerReady = putMVar mvar () } }
    E.bracket (forkIO $ server sc') killThread $ \_ -> client mvar
  where
    client mvar = do
        () <- takeMVar mvar
        C.run cc (\conn -> do
            wait1RTTReady conn
            threadDelay 2000000) `shouldThrow` selector
    server sc' =
        E.handle (\(E.SomeException _) -> return ()) $ S.run sc' $ \conn -> do
            wait1RTTReady conn
            threadDelay 2000000

-- | Client detects the error and sends ConnectionClose itself.
testClientExpectError :: ClientConfig -> ServerConfig -> (QUICException -> Bool) -> IO ()
testClientExpectError cc sc selector = do
    mvar <- newEmptyMVar
    smgr <- newSessionManager
    let sc' = sc { scSessionManager = smgr
                 , scHooks = (scHooks sc) { onServerReady = putMVar mvar () } }
    E.bracket (forkIO $ server sc') killThread $ \_ -> client mvar
  where
    client mvar = do
        () <- takeMVar mvar
        C.run cc (\conn -> do
            wait1RTTReady conn
            threadDelay 2000000) `shouldThrow` selector
    server sc' =
        E.handle (\(E.SomeException _) -> return ()) $ S.run sc' $ \conn -> do
            wait1RTTReady conn
            threadDelay 2000000

testDatagram1RTT :: ClientConfig -> ServerConfig -> Bool -> IO ()
testDatagram1RTT cc sc expectServerData = do
    mvar <- newEmptyMVar
    smgr <- newSessionManager
    let sc' = sc { scSessionManager = smgr
                 , scHooks = (scHooks sc) { onServerReady = putMVar mvar () } }
    E.bracket (forkIO $ server sc') killThread $ \_ -> client mvar
  where
    client mvar = do
        () <- takeMVar mvar
        C.run cc $ \conn -> do
            waitEstablished conn
            sendDatagram conn "client_data"
            when expectServerData $ do
                recv <- recvDatagram conn
                recv `shouldBe` "server_data"
    server sc' = do
        S.run sc' $ \conn -> do
            waitEstablished conn
            recv <- recvDatagram conn
            when (BS.length recv == 0 || recv == "hello") $ void (recvDatagram conn)
            when expectServerData $ sendDatagram conn "server_data"


testDatagram0RTT :: ClientConfig -> ServerConfig -> IO ()
testDatagram0RTT cc1 sc1 = do
    mvar <- newEmptyMVar
    smgr <- newSessionManager

    -- Phase 1: initial connection to get resumption info
    let scInit = sc1 { scSessionManager = smgr, scUse0RTT = True, scHooks = (scHooks sc1) { onServerReady = putMVar mvar () } }

    res <- E.bracket (forkIO $ S.run scInit (\c -> waitEstablished c >> threadDelay 100000)) killThread $ \_ -> do
        takeMVar mvar
        C.run cc1 $ \conn -> do
            waitEstablished conn
            threadDelay 50000
            getResumptionInfo conn

    -- Phase 2: 0-RTT connection with datagram
    let cc2 = cc1 { ccResumption = res, ccUse0RTT = True }

    mvar2 <- newEmptyMVar
    let sc0RTT = scInit { scHooks = (scHooks sc1) { onServerReady = putMVar mvar2 () } }

    E.bracket (forkIO $ server0RTT sc0RTT) killThread $ \_ -> client0RTT cc2 mvar2
  where
    client0RTT cc2 mvar2 = do
        () <- takeMVar mvar2
        C.run cc2 $ \conn -> do
            sendDatagram conn "0rtt_client_data"
            waitEstablished conn
            threadDelay 50000
    server0RTT sc = S.run sc $ \conn -> do
        waitEstablished conn
        info <- getConnectionInfo conn
        when (handshakeMode info == RTT0) $ do
            recv <- recvDatagram conn
            recv `shouldBe` "0rtt_client_data"

testDatagram0RTTDowngrade :: ClientConfig -> ServerConfig -> ServerConfig -> IO ()
testDatagram0RTTDowngrade cc1 scInit scDowngrade = do
    mvar <- newEmptyMVar
    smgr <- newSessionManager

    -- Phase 1: initial connection to get resumption info
    let scInit' = scInit { scSessionManager = smgr, scUse0RTT = True, scHooks = (scHooks scInit) { onServerReady = putMVar mvar () } }

    res <- E.bracket (forkIO $ S.run scInit' (\c -> waitEstablished c >> threadDelay 100000)) killThread $ \_ -> do
        takeMVar mvar
        C.run cc1 $ \conn -> do
            waitEstablished conn
            threadDelay 50000
            getResumptionInfo conn

    -- Phase 2: reconnect with downgraded server params; client should detect and reject
    let cc2 = cc1 { ccResumption = res, ccUse0RTT = True }

    mvar2 <- newEmptyMVar
    let scDowngrade' = scDowngrade { scSessionManager = smgr, scUse0RTT = True, scHooks = (scHooks scDowngrade) { onServerReady = putMVar mvar2 () } }

    E.bracket (forkIO $ server scDowngrade') killThread $ \_ ->
        client mvar2 cc2
  where
    server sc =
        E.handle (\(E.SomeException _) -> return ()) $ S.run sc $ \conn -> do
            waitEstablished conn
            threadDelay 2000000
    client mvar2 cc2 = do
        () <- takeMVar mvar2
        C.run cc2 (\_ -> threadDelay 2000000) `shouldThrow` isWrongDatagramSize
