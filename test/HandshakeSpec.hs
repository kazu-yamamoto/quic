{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module HandshakeSpec where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import qualified Data.ByteString as BS
import Data.IORef
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB
import Network.TLS (Group (..), HandshakeMode13 (..))
import qualified Network.TLS as TLS
import qualified System.Timeout as Timeout
import Test.Hspec

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
    let sc0 =
            sc0'
                { scSessionManager = smgr
                , scHooks =
                    (scHooks sc0')
                        { onServerReady = putMVar var ()
                        }
                }
    -- With a timeout: 'run' reports a server it could not start, but it is
    -- reported to whoever forked it, and that is not us.  Without this the
    -- take never returns and the whole suite stops rather than failing.
    let waitS =
            Timeout.timeout 5000000 (takeMVar var) >>= \r -> case r of
                Just () -> return ()
                Nothing -> expectationFailure "server never became ready"
    describe "handshake" $ do
        it "can handshake in the normal case" $ do
            let cc = testClientConfig
                sc = sc0
            testHandshake cc sc waitS FullHandshake
        it "can request and accept a client certificate" $ do
            let TLS.Credentials credentials = scCredentials sc0
            credential <- case credentials of
                [] ->
                    expectationFailure "test server has no credentials"
                        >> fail "missing credentials"
                cred : _ -> pure cred
            let clientHooks =
                    (ccTlsHooks testClientConfig)
                        { TLS.onCertificateRequest = const (pure (Just credential))
                        }
                serverHooks =
                    (scTlsHooks sc0)
                        { TLS.onClientCertificate = const (pure TLS.CertificateUsageAccept)
                        , TLS.onUnverifiedClientCert = pure True
                        }
                cc = testClientConfig{ccTlsHooks = clientHooks}
                sc =
                    sc0
                        { scWantClientCert = True
                        , scTlsHooks = serverHooks
                        }
            testHandshake cc sc waitS FullHandshake
        it "can handshake in the case of TLS hello retry" $ do
            let cc = testClientConfig
                sc = sc0{scGroups = [P256], scGroupsTLS13 = [[P256]]}
            testHandshake cc sc waitS HelloRetryRequest
        it "can handshake in the case of QUIC retry" $ do
            let cc = testClientConfig
                sc = sc0{scRequireRetry = True}
            testHandshake cc sc waitS FullHandshake
        it "can handshake in the case of resumption" $ do
            let cc = testClientConfig
                sc = sc0
            testHandshake2 cc sc waitS (FullHandshake, PreSharedKey) False
        it "can handshake in the case of 0-RTT" $ do
            let cc = testClientConfig
                sc = sc0{scUse0RTT = True}
            testHandshake2 cc sc waitS (FullHandshake, RTT0) True
        it "keeps 0-RTT within the limits the previous connection gave" $ do
            let cc = testClientConfig
                sc =
                    sc0
                        { scUse0RTT = True
                        , scParameters =
                            (scParameters sc0)
                                { initialMaxData = limit
                                , initialMaxStreamDataBidiRemote = limit
                                }
                        }
            test0RTTFlowControl cc sc waitS
        it "keeps a resumed connection to the limits the server gives now" $ do
            testLoweredLimits testClientConfig sc0 waitS
                `shouldReturn` (PreSharedKey, 3)
        it "refuses 0-RTT accepted with the limits lowered" $ do
            testLowered0RTT testClientConfig sc0{scUse0RTT = True} waitS
                `shouldThrow` protocolViolation
        it "MUST send FRAME_ENCODING_ERROR on an empty NEW_TOKEN [Transport 19.7]" $ do
            let sc = sc0{scHooks = (scHooks sc0){onPlainCreated = emptyNewToken}}
            E.bracket (forkIO $ S.run sc $ \_ -> threadDelay 2000000) killThread $ \_ -> do
                waitS
                C.run testClientConfig (\_ -> threadDelay 1000000)
                    `shouldThrow` frameEncodingErrorSent
        it "sends 0-RTT data without waiting for the handshake" $ do
            let sc = sc0{scUse0RTT = True}
            test0RTTSendsEarly sc waitS
        it "fails with unknown server certificate" $ do
            let cc1 =
                    testClientConfig
                        { ccValidate = True -- ouch, default should be reversed
                        }
                cc2 = testClientConfig
                sc = sc0
                certificateRejected e
                    | TransportErrorIsSent te@(TransportError _) _ <- e =
                        te == cryptoError TLS.CertificateUnknown
                    | otherwise = False
            testHandshake3 cc1 cc2 sc waitS certificateRejected
        it "fails with no group in common" $ do
            let cc1 = testClientConfig{ccGroups = [X25519]}
                cc2 = testClientConfig{ccGroups = [P256]}
                sc = sc0{scGroups = [P256], scGroupsTLS13 = [[P256]]}
                handshakeFailure e
                    | TransportErrorIsReceived te@(TransportError _) _ <- e =
                        te == cryptoError TLS.HandshakeFailure
                    | otherwise = False
            testHandshake3 cc1 cc2 sc waitS handshakeFailure
        it "fails with no version in common" $ do
            let cc1 = testClientConfig{ccVersion = Version1, ccVersions = [Version1]}
                cc2 = testClientConfig
                sc = sc0{scVersions = [Version2]}
                failed VersionNegotiationFailed = True
                failed _ = False
            testHandshake3 cc1 cc2 sc waitS failed
        it "keeps serving after datagrams too large to receive" $ do
            mvar <- newEmptyMVar
            let serv conn = waitEstablished conn >> putMVar mvar ()
            E.bracket (forkIO $ S.run sc0 serv) killThread $ \_ -> do
                waitS
                -- Winsock fails a receive into a buffer too small for the
                -- datagram, where POSIX truncates it.
                sendOversized 3
                r <- Timeout.timeout 5000000 $
                    C.run testClientConfig $ \conn -> do
                        waitEstablished conn
                        takeMVar mvar
                r `shouldBe` Just ()
        it "can handshake with large HE from a client" $ do
            let cc0 = testClientConfig
                params =
                    (ccParameters cc0)
                        { grease = Just (BS.pack (replicate 2400 0))
                        }
                cc = cc0{ccParameters = params}
                sc = sc0
            testHandshake cc sc waitS FullHandshake
        it "can handshake with large EE from a server (3-times rule)" $ do
            let cc = testClientConfig
                params =
                    (scParameters sc0)
                        { grease = Just (BS.pack (replicate 3800 0))
                        }
                sc = sc0{scParameters = params}
            testHandshake cc sc waitS FullHandshake

-- | Datagrams larger than the server's receive buffer, to the test server.
sendOversized :: Int -> IO ()
sendOversized n = do
    let hints = NS.defaultHints{NS.addrSocketType = NS.Datagram}
    addr : _ <- NS.getAddrInfo (Just hints) (Just "127.0.0.1") (Just "15003")
    E.bracket (NS.openSocket addr) NS.close $ \s ->
        replicateM_ n $ NSB.sendTo s (BS.replicate 4000 0) (NS.addrAddress addr)

onE :: IO b -> IO a -> IO a
onE h b = E.onException b h

testHandshake
    :: ClientConfig -> ServerConfig -> IO () -> HandshakeMode13 -> IO ()
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

-- | The limit the server gives, which the second connection sends more than.
limit :: Int
limit = 1024

-- | A client sending 0-RTT is held to the limits the previous connection
--   gave it (RFC 9000 Sec 7.4.1).
--
-- 0-RTT stream data used to bypass the flow control check altogether: it
-- went onto the send queue and the window was told about it afterwards, so
-- a resuming client spent a connection window it had not been given.  A
-- server that counts -- ours does -- answers that with FLOW_CONTROL_ERROR
-- before the handshake has even finished.
--
-- The data has to be written before the handshake completes for any of this
-- to be exercised, so this does not go through 'query', which waits for the
-- connection to be established first.
test0RTTFlowControl :: ClientConfig -> ServerConfig -> IO () -> IO ()
test0RTTFlowControl cc1 sc waitS = do
    mvar <- newEmptyMVar
    E.bracket (forkIO $ server mvar) killThread $ \_ -> client mvar
  where
    content = BS.replicate (limit * 4) 97
    client mvar = do
        waitS
        res <- C.run cc1 $ \conn -> do
            query "first" conn
            threadDelay 50000
            getResumptionInfo conn
        threadDelay 50000
        let cc2 = cc1{ccResumption = res, ccUse0RTT = True}
        C.run cc2 $ \conn -> do
            s <- stream conn
            sendStream s content
            shutdownStream s
            void $ recvStream s 1024
        takeMVar mvar
    server mvar = S.run sc serv
      where
        serv conn = do
            s <- acceptStream conn
            bs <- recvAll s id
            sendStream s "bye"
            closeStream s
            when (bs == content) $ putMVar mvar ()
    recvAll s build = do
        bs <- recvStream s 1024
        if BS.null bs
            then return $ BS.concat $ build []
            else recvAll s (build . (bs :))

-- | The remembered limits are what let 0-RTT carry anything at all.
--
-- The connection's own send limit starts at zero and the handshake is what
-- raises it, so a client that checks the connection window before the
-- handshake -- which it has to, see above -- has nothing to spend until the
-- handshake is over, and 0-RTT carries no data.  What it may spend is what
-- the previous connection gave it.
--
-- Every packet from the server is dropped here, so the handshake cannot
-- finish and a send that waits for it waits for good.
test0RTTSendsEarly :: ServerConfig -> IO () -> IO ()
test0RTTSendsEarly sc waitS =
    E.bracket (forkIO server) killThread $ \_ -> do
        waitS
        resVar <- newEmptyMVar
        withPipe (DropServerPacket []) $ do
            res <- C.run testClientConfigR $ \conn -> do
                query "first" conn
                threadDelay 50000
                getResumptionInfo conn
            putMVar resVar res
        res <- takeMVar resVar
        threadDelay 50000
        let cc =
                testClientConfigR
                    { ccResumption = res
                    , ccUse0RTT = True
                    }
        sent <- newEmptyMVar
        -- The client is held open past the send so that the connection does
        -- not tear down before the take below, and killed with the test so
        -- that it does not outlive it.  Left to run out its own delay, it
        -- went on sending Initial packets to the port the relay had just
        -- given up, and the relay of whatever test came next latched onto
        -- it: that test's client was then ignored for every datagram it
        -- sent and failed on the idle timeout, ten seconds later and with
        -- nothing to say why.
        let client = ignoreQUIC $ C.run cc $ \conn -> do
                s <- stream conn
                sendStream s $ BS.replicate limit 97
                putMVar sent ()
                threadDelay 5000000
        withPipe (DropServerPacket [0 .. 50]) $
            E.bracket (forkIO client) killThread $ \_ ->
                Timeout.timeout 2000000 (takeMVar sent) `shouldReturn` Just ()
  where
    server = S.run sc $ \conn -> do
        s <- acceptStream conn
        void $ recvStream s 1024
        sendStream s "bye"
        closeStream s
    ignoreQUIC :: IO () -> IO ()
    ignoreQUIC act = act `E.catch` \(_ :: E.SomeException) -> return ()

testHandshake2
    :: ClientConfig
    -> ServerConfig
    -> IO ()
    -> (HandshakeMode13, HandshakeMode13)
    -> Bool
    -> IO ()
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
        let cc2 =
                cc1
                    { ccResumption = res
                    , ccUse0RTT = use0RTT
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
            when (bs == "second") $ putMVar mvar ()

testHandshake3
    :: ClientConfig
    -> ClientConfig
    -> ServerConfig
    -> IO ()
    -> (QUICException -> Bool)
    -> IO ()
testHandshake3 cc1 cc2 sc waitS selector = do
    mvar <- newEmptyMVar
    E.bracket (forkIO $ server mvar) killThread $ \_ -> client mvar
  where
    client mvar = do
        waitS
        C.run cc1 (query "first") `shouldThrow` selector
        C.run cc2 (query "second") `shouldReturn` ()
        takeMVar mvar
    server mvar = S.run sc $ \conn -> do
        s <- acceptStream conn
        recvStream s 1024 `shouldReturn` "second"
        sendStream s "bye"
        closeStream s
        putMVar mvar ()

-- | A first connection to a server allowing a hundred streams, for its
--   resumption information.
resumeFrom :: ClientConfig -> ServerConfig -> IO () -> IO ResumptionInfo
resumeFrom cc sc waitS =
    E.bracket (forkIO $ S.run sc1 serv) killThread $ \_ -> do
        waitS
        C.run cc $ \conn -> do
            s <- stream conn
            sendStream s "first"
            shutdownStream s
            _ <- recvStream s 1024
            threadDelay 50000
            getResumptionInfo conn
  where
    sc1 = sc{scParameters = (scParameters sc){initialMaxStreamsBidi = 100}}
    serv conn = do
        s <- acceptStream conn
        _ <- recvStream s 1024
        sendStream s "bye"
        closeStream s

-- | The same server, as far as its session tickets go, then allowing
--   three streams.  RFC 9000 Sec 7.4.1 has the client keep to what it
--   remembers only for 0-RTT.  The limits only ever rose on the client, so
--   a resumed connection went on opening streams up to the hundred, and the
--   server closed it with STREAM_LIMIT_ERROR.
--
-- Answers how the second connection went and how many streams it opened
-- in a second and a half.
testLoweredLimits
    :: ClientConfig -> ServerConfig -> IO () -> IO (HandshakeMode13, Int)
testLoweredLimits cc1 sc waitS = do
    res <- resumeFrom cc1 sc waitS
    threadDelay 100000
    E.bracket (forkIO $ S.run sc2 serv) killThread $ \_ -> do
        waitS
        C.run cc1{ccResumption = res} $ \conn -> do
            opened <- newIORef (0 :: Int)
            _ <- Timeout.timeout 1500000 $ forever $ do
                s <- stream conn
                sendStream s "x"
                atomicModifyIORef' opened $ \x -> (x + 1, ())
            (,) <$> (handshakeMode <$> getConnectionInfo conn) <*> readIORef opened
  where
    sc2 = sc{scParameters = (scParameters sc){initialMaxStreamsBidi = 3}}
    serv conn = forever $ void $ acceptStream conn

-- | As above, but with 0-RTT, which the server accepts with fifty streams
--   where it gave a hundred before: RFC 9000 Sec 7.4.1 says it MUST NOT.
--   The client opens one stream, within either, so that it is the client
--   that notices.
testLowered0RTT :: ClientConfig -> ServerConfig -> IO () -> IO ()
testLowered0RTT cc1 sc waitS = do
    res <- resumeFrom cc1 sc waitS
    threadDelay 100000
    E.bracket (forkIO $ S.run sc2 serv) killThread $ \_ -> do
        waitS
        C.run cc1{ccResumption = res, ccUse0RTT = True} $ \conn -> do
            s <- stream conn
            sendStream s "x"
            threadDelay 1000000
  where
    sc2 = sc{scParameters = (scParameters sc){initialMaxStreamsBidi = 50}}
    serv conn = forever $ void $ acceptStream conn

emptyNewToken :: EncryptionLevel -> Plain -> Plain
emptyNewToken _ plain = plain{plainFrames = map empty $ plainFrames plain}
  where
    empty (NewToken _) = NewToken ""
    empty f = f

frameEncodingErrorSent :: QUICException -> Bool
frameEncodingErrorSent (TransportErrorIsSent FrameEncodingError _) = True
frameEncodingErrorSent _ = False

protocolViolation :: QUICException -> Bool
protocolViolation (TransportErrorIsSent ProtocolViolation _) = True
protocolViolation _ = False
