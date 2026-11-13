{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module IOSpec where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM (atomically, readTVarIO)
import qualified Control.Exception as E
import Control.Monad
import Data.Bits (shiftR)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as Short
import Data.IORef
import qualified Data.IntMap.Strict as IntMap
import Data.Maybe (isNothing)
import qualified Data.Sequence as Seq
import GHC.Conc (getUncaughtExceptionHandler, setUncaughtExceptionHandler)
import Network.Control (txfSent)
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB
import System.Directory (listDirectory)
import System.FilePath ((</>))
import qualified System.Timeout as Timeout
import Test.Hspec

import Network.QUIC
import qualified Network.QUIC.Client as C
import Network.QUIC.Internal
import Network.QUIC.Server

import Config
import PacketSpec (makeConnections)

spec :: Spec
spec = do
    runIO prepareQlog
    sc0 <- runIO makeTestServerConfigR
    var <- runIO newEmptyMVar
    let sc =
            sc0
                { scHooks =
                    (scHooks sc0)
                        { onServerReady = putMVar var ()
                        }
                }
    let cc = setClientQlog testClientConfigR
    -- With a timeout: 'run' reports a server it could not start, but it is
    -- reported to whoever forked it, and that is not us.  Without this the
    -- take never returns and the whole suite stops rather than failing.
    let waitS =
            Timeout.timeout 5000000 (takeMVar var) >>= \r -> case r of
                Just () -> return ()
                Nothing -> expectationFailure "server never became ready"
    -- RFC 9000 Sec 6.2 and 17.2.5.2: once a packet from the server has been
    -- processed, a Version Negotiation or Retry packet is to be discarded.
    -- The connection has moved to Version2 by compatible negotiation.
    describe "a forged packet after the handshake" $ do
        it "ignores Version Negotiation" $
            testInjected cc sc waitS $ \dcid scid ->
                encodeVersionNegotiationPacket $
                    VersionNegotiationPacket dcid scid [Version1]
        it "ignores Retry" $
            testInjected cc sc waitS $ \dcid scid ->
                encodeRetryPacket $
                    RetryPacket Version2 dcid (toCID "forged") "token" (Left scid)
    -- The offset of queued data used to be taken when it was sent.  A
    -- sender cancelled after taking an entry from the queue lost it, and
    -- the next entry was then sent at its offset (HTTP/3 got DATA where
    -- its HEADERS were and closed with H3_FRAME_UNEXPECTED).
    describe "queued stream data" $
        it "has its offset from when it was queued" $ do
            scq <- makeTestServerConfig
            (clientConn, _) <- makeConnections scq Version1
            strm <- addStream clientConn 0
            setTxMaxData clientConn 1000
            setTxMaxStreamData strm 1000
            sendStream strm "HEADER"
            sendStream strm $ BS.replicate 16 0
            let offset (TxStreamData _ off _ len _) = (off, len)
            -- The first one taken and lost: the second keeps its offset.
            _ <- takeSendStreamQ clientConn
            offset <$> takeSendStreamQ clientConn `shouldReturn` (6, 16)
    -- RFC 9000 Sec 13.3: stream data is resent unless the stream is reset.
    describe "a lost STREAM frame" $
        it "is not resent once its stream is reset" $ do
            scr <- makeTestServerConfig
            (clientConn, _) <- makeConnections scr Version1
            s0 <- addStream clientConn 0
            s4 <- addStream clientConn 4
            now <- getTimeMicrosecond
            let frames = [StreamF 0 0 ["zero"] False, StreamF 4 0 ["four"] False]
                hdr = Short $ toCID ""
                spkt =
                    ( mkSentPacket
                        1
                        RTT1Level
                        (PlainPacket hdr (Plain (Flags 0) 1 frames 0))
                        emptyPeerPacketNumbers
                        True
                    )
                        { spTimeSent = now
                        , spStreamResets =
                            StreamResets [(0, streamResetTx s0), (4, streamResetTx s4)]
                        }
            -- Reset after it was sent: the stream also leaves the table.
            resetStream s0 $ ApplicationProtocolError 0
            gone <- isNothing <$> findStream clientConn 0
            gone `shouldBe` True
            retransmit (connLDCC clientConn) $ Seq.singleton spkt
            Just (PlainPacket _ plain, resets) <-
                atomically $ takeRetransSTM clientConn RTT1Level
            adjustForRetransmit clientConn resets (plainFrames plain)
                `shouldReturn` [StreamF 4 0 ["four"] False]
    -- RFC 9000 Sec 4.1: two streams sending at once used to both see the
    -- same connection window and queue twice what MAX_DATA allowed.
    describe "the connection window" $
        it "is not given to two streams sending at once" $ do
            scw <- makeTestServerConfig
            (clientConn, _) <- makeConnections scw Version1
            overs <- forM [0 .. 999] $ \i -> do
                s1 <- addStream clientConn (8 * i)
                s2 <- addStream clientConn (8 * i + 4)
                setTxMaxStreamData s1 100
                setTxMaxStreamData s2 100
                base <- txfSent <$> atomically (readConnectionFlowTx clientConn)
                setTxMaxData clientConn $ base + 100
                let send s = Timeout.timeout 1000 $ sendStream s $ BS.replicate 100 0
                _ <- concurrently (send s1) (send s2)
                sent <- txfSent <$> atomically (readConnectionFlowTx clientConn)
                return $ sent - base
            filter (> 100) overs `shouldBe` []
    describe "a stateless reset to the client" $
        it "ends the connection with ConnectionIsReset" $
            testStatelessResetReceived cc sc waitS
    describe "max_udp_payload_size" $ do
        it "bounds the datagrams each side sends" $ do
            let small p = p{maxUdpPayloadSize = 1200}
                cc' = cc{ccParameters = small $ ccParameters cc}
                sc' = sc{scParameters = small $ scParameters sc}
            ref <- newIORef []
            withPipe (RecordSizes ref) $ testEcho cc' sc' waitS 20
            sizes <- readIORef ref
            [siz | (True, siz) <- sizes] `shouldSatisfy` all (<= 1200)
            [siz | (False, siz) <- sizes] `shouldSatisfy` all (<= 1200)
            -- Data went both ways in full-sized packets.
            [siz | (True, siz) <- sizes] `shouldSatisfy` elem 1200
            [siz | (False, siz) <- sizes] `shouldSatisfy` elem 1200
    describe "STOP_SENDING in a burst" $ do
        it "resets every stream (20)" $ testStopMany cc sc waitS 20
        it "resets every stream (40)" $ testStopMany cc sc waitS 40
    describe "handshake" $ do
        it "can exchange data when the server's first flight is lost" $ do
            withPipe (DropServerPacket [0, 1, 2]) $ testSendRecv cc sc waitS 20
    describe "send & recv" $ do
        it "can exchange data on random dropping" $ do
            withPipe (Randomly 20) $ testSendRecv cc sc waitS 1000
        it "can exchange data on server 0" $ do
            withPipe (DropServerPacket [0]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 1" $ do
            withPipe (DropServerPacket [1]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 2" $ do
            withPipe (DropServerPacket [2]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 3" $ do
            withPipe (DropServerPacket [3]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 4" $ do
            withPipe (DropServerPacket [4]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 5" $ do
            withPipe (DropServerPacket [5]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 6" $ do
            withPipe (DropServerPacket [6]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 7" $ do
            withPipe (DropServerPacket [7]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 8" $ do
            withPipe (DropServerPacket [8]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 9" $ do
            withPipe (DropServerPacket [9]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 10" $ do
            withPipe (DropServerPacket [10]) $ testSendRecv cc sc waitS 20
        it "can exchange data on server 11" $ do
            withPipe (DropServerPacket [11]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 0" $ do
            withPipe (DropClientPacket [0]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 1" $ do
            withPipe (DropClientPacket [1]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 2" $ do
            withPipe (DropClientPacket [2]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 3" $ do
            withPipe (DropClientPacket [3]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 4" $ do
            withPipe (DropClientPacket [4]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 5" $ do
            withPipe (DropClientPacket [5]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 6" $ do
            withPipe (DropClientPacket [6]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 7" $ do
            withPipe (DropClientPacket [7]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 8" $ do
            withPipe (DropClientPacket [8]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 9" $ do
            withPipe (DropClientPacket [9]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 10" $ do
            withPipe (DropClientPacket [10]) $ testSendRecv cc sc waitS 20
        it "can exchange data on client 11" $ do
            withPipe (DropClientPacket [11]) $ testSendRecv cc sc waitS 20
    describe "recvStream" $ do
        -- https://github.com/kazu-yamamoto/quic/pull/54
        it "don't block if client stop sending first" $ do
            withPipe (Randomly 20) $ testRecvStreamClientStopFirst cc sc waitS
        it "don't block if server stop sending first" $ do
            withPipe (Randomly 20) $ testRecvStreamServerStopFirst cc sc waitS
        -- RFC 9000: https://www.rfc-editor.org/rfc/rfc9000.html
        -- Section 3.5 says STOP_SENDING asks the peer to send RESET_STREAM.
        -- Sections 4.5 and 19.4 define RESET_STREAM Final Size as the
        -- number of bytes sent by the RESET_STREAM sender.
        it "sends RESET_STREAM with the bytes sent as final size" $ do
            withPipe (DropClientPacket []) $ testResetStreamFinalSize cc sc waitS
        it "sends RESET_STREAM with the bytes queued as final size" $ do
            withPipe (DropClientPacket []) $ testResetAfterSend cc sc waitS
        it "tells a stream that was reset from one that ended" $ do
            withPipe (DropClientPacket []) $ testResetReceived cc sc waitS
    describe "closed stream" $ do
        it "ignores a late copy of the data it received on a stream it opened" $ do
            withPipe (DelayServerPacket 300) $ testLateCopy False cc sc waitS
        it "ignores a late copy of the data it received on a stream the peer opened" $ do
            withPipe (DelayClientPacket 300) $ testLateCopy True cc sc waitS
    -- RFC 9000 Sec 17.2.3: 0-RTT goes from client to server only.
    describe "a frame received in 0-RTT" $ do
        let replied serverConn = do
                out <- atomically $ takeOutputSTM serverConn
                case out of
                    OutControl lvl frames -> return (lvl, frames)
                    _ -> fail "no control frames"
        it "has its ACK sent in 1-RTT" $ do
            scz <- makeTestServerConfig
            (_, serverConn) <- makeConnections scz Version1
            processFrame serverConn RTT0Level Ping
            fst <$> replied serverConn `shouldReturn` RTT1Level
        it "has its RESET_STREAM sent in 1-RTT" $ do
            scz <- makeTestServerConfig
            (_, serverConn) <- makeConnections scz Version1
            _ <- addStream serverConn 0
            processFrame serverConn RTT0Level $ StopSending 0 $ ApplicationProtocolError 0
            (lvl, frames) <- replied serverConn
            lvl `shouldBe` RTT1Level
            frames `shouldSatisfy` any isResetStream
    describe "stream limits" $ do
        -- #86: the number the peer may have open is no longer fixed.
        it "announces a raised limit at once and holds a lowered one" $ do
            scl <- makeTestServerConfig
            (_, serverConn) <- makeConnections scl Version1
            let initial = initialMaxStreamsBidi $ getMyParameters serverConn
            setMaxBidiStreams serverConn $ initial + 10
            out <- atomically $ takeOutputSTM serverConn
            case out of
                OutControl RTT1Level [MaxStreams Bidirectional n] -> n `shouldBe` initial + 10
                _ -> expectationFailure "no MAX_STREAMS"
            -- MAX_STREAMS cannot go down, and closing one stream of many
            -- under a lower target gives the peer no new one.
            setMaxBidiStreams serverConn 1
            atomically (isEmptyOutputSTM serverConn) `shouldReturn` True
            checkStreamIdRoom serverConn Bidirectional `shouldReturn` Nothing
        it "keeps the peer's open bidirectional streams within the limit" $ do
            withPipe (DropClientPacket []) $ testOpenStreams cc sc waitS
        it "raises the limit on unidirectional streams by their own number" $ do
            withPipe (DropClientPacket []) $ testUniStreams cc sc waitS
        it "ignores STOP_SENDING for a unidirectional stream it has closed" $ do
            withPipe (DropClientPacket []) $ testStopClosedUni cc sc waitS
    describe "a stream closed before the peer finishes it" $ do
        it "is forgotten once the peer answers STOP_SENDING" $ do
            withPipe (DropClientPacket []) $ testDepartedForgotten cc sc waitS
        it "is kept within the limit when the peer does not answer" $ do
            withPipe (DropClientPacket []) $ testDepartedBounded cc sc waitS
        it "is forgotten when its FIN crosses the close" $ do
            withPipe (DropClientPacket []) $ testFinCrossesClose cc sc waitS
    describe "the server's path" $ do
        it "stays put for a short header packet that does not decrypt" $
            testForgedPath cc sc waitS $ \_ (CID dcid) ->
                BS.concat [BS.singleton 0x40, Short.fromShort dcid, BS.replicate 1100 0x11]
        it "stays put for a Handshake packet that does not decrypt" $
            testForgedPath cc sc waitS $ \ver (CID dcid) ->
                let Version v = ver
                    typ = if ver == Version2 then 0x30 else 0x20
                 in BS.concat
                        [ BS.singleton (0xc0 + typ)
                        , BS.pack [fromIntegral (v `shiftR` n) | n <- [24, 16, 8, 0]]
                        , BS.singleton (fromIntegral $ Short.length dcid)
                        , Short.fromShort dcid
                        , BS.pack [0, 0x44, 0x00]
                        , BS.replicate 1024 0x11
                        ]
        it "follows a client that rebinds" $ testRebindPath cc sc waitS
        it "goes back when the new one is not validated" $
            testSpuriousMigration cc sc waitS 1500000
        -- RFC 9000 Sec 9.3.3.  The new path answers nothing, so a
        -- PATH_CHALLENGE in the client's qlog came on the old one.
        -- The server's socket for a path is the one its packets came in
        -- on.  It used to be the last socket any packet came in on, and the
        -- IPv4 old path was then challenged through the IPv6 socket.
        it "sends each path's packets on that path's socket" $ do
            let sc46 = sc{scAddresses = [("127.0.0.1", 15003), ("::1", 15003)]}
            testSpuriousMigration6 cc sc46 waitS
        it "challenges the old path too" $
            withTempDir "quic-old-path-qlog" $ \dir -> do
                testSpuriousMigration cc{ccQLog = Just dir} sc waitS 1500000
                logs <- listDirectory dir >>= mapM (BS.readFile . (dir </>))
                any ("path_challenge" `BS.isInfixOf`) logs `shouldBe` True
    describe "a stateless reset" $ do
        it "is smaller than the packet it answers" $ do
            withAsync (run sc $ \_ -> return ()) $ \_ -> do
                waitS
                -- A reset of the server's, sent back to it, as another
                -- server would.  It used to be answered at the same size.
                sizes <- resetSizes [1280, 640, 60]
                sizes `shouldBe` [Just 640, Just 320, Just 30]
    describe "the client's socket" $ do
        it "is closed when the peer ends the connection" $ do
            withPipe (DropClientPacket []) $ testSocketClosed cc sc waitS
    describe "the peer closing with NO_ERROR" $ do
        it "wakes a client waiting in recvStream" $ do
            withPipe (DropClientPacket []) $
                testPeerClosed cc sc waitS Nothing $ \conn -> do
                    strm <- stream conn
                    sendStream strm "ping"
                    void $ recvStream strm 1024
                    recvStream strm 1024
        it "wakes a client waiting in acceptStream" $ do
            withPipe (DropClientPacket []) $
                testPeerClosed cc sc waitS Nothing $ \conn -> do
                    strm <- stream conn
                    sendStream strm "ping"
                    void $ recvStream strm 1024
                    void $ acceptStream conn
                    return ""
        it "lets a client that is not waiting finish" $ do
            withPipe (DropClientPacket []) $
                testPeerClosed cc sc waitS (Just "done") $ \conn -> do
                    strm <- stream conn
                    sendStream strm "ping"
                    void $ recvStream strm 1024
                    threadDelay 300000
                    return "done"
    describe "stream state" $ do
        it "can still send after the peer's RESET_STREAM" $ do
            withPipe (DropClientPacket []) $ testSendAfterReset cc sc waitS
        it "cannot send after the peer's STOP_SENDING" $ do
            withPipe (DropClientPacket []) $ testStopSending cc sc waitS
        it "ends the stream for the reader when it is reset" $ do
            withPipe (DropClientPacket []) $ testRecvAfterReset cc sc waitS
        it "accepts a stream the peer only reset" $ do
            withPipe (DropClientPacket []) $ testResetOnly cc sc waitS
        it "accepts a reset that overtook the data it followed" $ do
            withPipe (DropClientPacket []) $ testResetOvertakes cc sc waitS
        it "accepts a stream the peer is only blocked on" $ do
            withPipe (DropClientPacket []) $ testDataBlockedOpens cc sc waitS
    describe "final size" $ do
        it "refuses a final size that is not the one already known" $ do
            withPipe (DropClientPacket []) $
                testFinalSize cc sc waitS [StreamF 0 0 ["ab"] True, StreamF 0 0 ["abcd"] True]
        it "refuses a final size below what the stream has reached" $ do
            withPipe (DropClientPacket []) $
                testFinalSize cc sc waitS [StreamF 0 0 ["abcd"] False, StreamF 0 0 ["ab"] True]
        it "refuses stream data beyond the final size" $ do
            withPipe (DropClientPacket []) $
                testFinalSize cc sc waitS [StreamF 0 0 ["ab"] True, StreamF 0 2 ["cd"] False]
        it "counts what the application never reads against the connection" $ do
            withPipe (DropClientPacket []) $ testCloseWithoutReading cc sc waitS
        it "counts what arrives after the application has closed the stream" $ do
            withPipe (DropClientPacket []) $ testCloseWhileArriving cc sc waitS
        it "counts a reset stream's final size against the connection" $ do
            withPipe (DropClientPacket []) $ testResetCountsAgainstTheWindow cc sc waitS
        it "holds a reset stream's final size to the stream's limit" $ do
            withPipe (DropClientPacket []) $ testResetOverStreamLimit cc sc waitS
        it "counts the gaps of a stream against the connection" $ do
            withPipe (DropClientPacket []) $ testGapCountsAgainstTheWindow cc sc waitS
        it "holds a closed stream to the stream's limit" $ do
            withPipe (DropClientPacket []) $
                testDepartedOverLimit (100000, 1000) cc sc waitS
        it "holds a closed stream to the connection's limit" $ do
            withPipe (DropClientPacket []) $
                testDepartedOverLimit (1000, 100000) cc sc waitS
    describe "closing" $ do
        it "tells the peer when the application gives up" $ do
            withPipe (DropClientPacket []) $ testServerThrows cc sc waitS
        it "tells the peer before waiting for the application" $ do
            withPipe (DropClientPacket []) $ testSlowApp cc sc waitS
        it "leaves nothing uncaught when stopped as a connection ends" $ do
            withPipe (DropClientPacket []) $ noUncaught $ testSlowApp cc sc waitS
    describe "port handover" $ do
        it "ignores a leftover datagram from the connection that just closed" $
            withPipeStray (Randomly 20) $
                testSendRecv cc sc waitS 20
    describe "concurrency" $ do
        it "can handle multiple clients" $ do
            withPipe (Randomly 20) $ testMultiSendRecv cc sc waitS 500
    describe "packing" $ do
        it "fits the frames of many streams with tiny writes into a packet" $ do
            withPipe (DropClientPacket []) $ testTinyWrites cc sc waitS
    describe "abortConnection" $ do
        it "can abort connection" $ do
            withPipe (Randomly 20) $ testAbort cc sc waitS

-- | Writing data to many, many streams doesn't cause a buffer overrun
testTinyWrites :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testTinyWrites cc sc0 waitS = do
    doneVar <- newChan
    withAsync (server doneVar) $ \_ -> client doneVar
  where
    nStreams = 400
    sc =
        sc0
            { scParameters =
                (scParameters sc0){initialMaxStreamsBidi = 2 * nStreams}
            }

    client doneVar = do
        waitS
        C.run cc $ \conn -> do
            strms <- replicateM nStreams (stream conn)
            forM_ strms $ \strm -> sendStream strm "a"
            threadDelay 200_000
            forM_ strms $ \strm -> sendStream strm "b"
            -- Wait for the server to have read both bytes of every stream
            -- before closing the connection.
            mres <- Timeout.timeout 10_000_000 $ replicateM_ nStreams $ readChan doneVar
            mres `shouldBe` Just ()

    server doneVar = run sc $ \conn -> forever $ do
        strm <- acceptStream conn
        void $ forkIO $ do
            consumeBytes strm 2
            writeChan doneVar ()

consumeBytes :: Stream -> Int -> IO ()
consumeBytes _ 0 = return ()
consumeBytes strm left = do
    bs <- recvStream strm 1024
    when (BS.null bs) $ expectationFailure "no enough bytes received"
    let len = BS.length bs
    when (len > left) $ expectationFailure "extra bytes received"
    consumeBytes strm (left - len)

assertEndOfStream :: Stream -> IO ()
assertEndOfStream strm = recvStream strm 1024 `shouldReturn` ""

testResetStreamFinalSize
    :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testResetStreamFinalSize cc0 sc waitS = do
    finalSizeVar <- newEmptyMVar
    doneVar <- newEmptyMVar
    let request = "open"
        payload = BS.replicate 1234 0
        hooks = (ccHooks cc0){onResetStreamReceived2 = record finalSizeVar}
        cc = cc0{ccHooks = hooks}
    withAsync (server request payload doneVar) $ \_ ->
        client cc request payload finalSizeVar doneVar
  where
    aerr = ApplicationProtocolError 0

    record finalSizeVar _strm _aerr finalSize = void $ tryPutMVar finalSizeVar finalSize

    client cc request payload finalSizeVar doneVar = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            sendStream strm request
            consumeBytes strm (BS.length payload)
            stopStream strm aerr
            mres <- Timeout.timeout 5000000 $ takeMVar finalSizeVar
            mres `shouldBe` Just (BS.length payload)
            putMVar doneVar ()

    server request payload doneVar = run sc $ \conn -> do
        strm <- acceptStream conn
        consumeBytes strm (BS.length request)
        sendStream strm payload
        takeMVar doneVar

-- | A reset straight after 'sendStream' finds most of the data still
--   queued.  The final size has to cover it, and none of it may follow the
--   RESET_STREAM: either makes the peer close with FINAL_SIZE_ERROR.
testResetAfterSend :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testResetAfterSend cc0 sc waitS = do
    finalSizeVar <- newEmptyMVar
    doneVar <- newEmptyMVar
    let hooks = (ccHooks cc0){onResetStreamReceived2 = record finalSizeVar}
        cc = cc0{ccHooks = hooks}
    withAsync (server doneVar) $ \_ -> client cc finalSizeVar doneVar
  where
    payload = BS.replicate 100000 0
    record finalSizeVar _strm _aerr finalSize = void $ tryPutMVar finalSizeVar finalSize

    client cc finalSizeVar doneVar = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            sendStream strm "open"
            mres <- Timeout.timeout 5000000 $ takeMVar finalSizeVar
            mres `shouldBe` Just (BS.length payload)
            -- The connection is still there once anything sent after the
            -- RESET_STREAM would have arrived.
            strm2 <- stream conn
            sendStream strm2 "ping"
            shutdownStream strm2
            recvStream strm2 4 `shouldReturn` "ping"
            putMVar doneVar ()

    server doneVar = run sc $ \conn -> do
        strm <- acceptStream conn
        consumeBytes strm 4
        sendStream strm payload
        resetStream strm $ ApplicationProtocolError 0
        strm2 <- acceptStream conn
        consumeBytes strm2 4
        sendStream strm2 "ping"
        shutdownStream strm2
        takeMVar doneVar

-- | One end has read a stream to its end and closed it while a packet for
--   it is still on the way.  That packet was taken for lost and its data sent
--   again, so what arrives late is a copy, well past the initial window of
--   256K.  It must not open the stream anew: the new stream holds the copy to
--   that window and calls it a flow control error, or else hands the
--   application a stream that was never opened.
testLateCopy :: Bool -> C.ClientConfig -> ServerConfig -> IO () -> IO ()
testLateCopy upload cc sc waitS =
    withAsync server $ \_ -> client
  where
    (upLen, downLen)
        | upload = (1000000, 10)
        | otherwise = (10, 1000000)

    client = do
        waitS
        C.run cc $ \conn -> do
            exchange conn
            -- The copy arrives while we wait.
            threadDelay 200000
            exchange conn
    exchange conn = do
        strm <- stream conn
        sendStream strm (BS.replicate upLen 0)
        shutdownStream strm
        consumeBytes strm downLen
        assertEndOfStream strm
        closeStream strm

    server = run sc $ \conn -> forever $ do
        strm <- acceptStream conn
        consumeBytes strm upLen
        assertEndOfStream strm
        sendStream strm (BS.replicate downLen 0)
        closeStream strm

-- | After a RESET_STREAM, 'recvStream' returns "" just as at the end of the
-- stream; 'resetReceived' tells the two apart.  The client ends one stream
-- and resets another, and the server looks at both.
testResetReceived :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testResetReceived cc sc waitS = do
    resultVar <- newEmptyMVar
    withAsync (server resultVar) $ \_ -> client resultVar
  where
    aerr = ApplicationProtocolError 7

    client resultVar = do
        waitS
        C.run cc $ \conn -> do
            strm0 <- stream conn
            sendStream strm0 "ended"
            shutdownStream strm0
            strm1 <- stream conn
            sendStream strm1 "reset"
            -- Let the data go first.
            threadDelay 100000
            resetStream strm1 aerr
            mres <- Timeout.timeout 5000000 $ takeMVar resultVar
            mres `shouldBe` Just (Nothing, Just aerr)

    server resultVar = run sc $ \conn -> do
        strm0 <- acceptStream conn
        strm1 <- acceptStream conn
        let drain strm = do
                bs <- recvStream strm 1024
                unless (BS.null bs) $ drain strm
        drain strm0
        drain strm1
        r0 <- resetReceived strm0
        r1 <- resetReceived strm1
        putMVar resultVar (r0, r1)
        threadDelay 1000000

-- | The server closes one stream in ten and keeps the others open; the
-- client opens streams for as long as it is let.  No more than
-- initial_max_streams_bidi may be open at once (RFC 9000, section 4.6).
--
-- The limit used to be raised to the highest stream opened plus the initial
-- number whenever a stream was closed, so that the client was given a whole
-- new window each time: over three thousand were held open within seconds.
testOpenStreams :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testOpenStreams cc sc waitS = do
    maxOpen <- newIORef (0 :: Int)
    withAsync (server maxOpen) $ \_ -> do
        client
        readIORef maxOpen
            >>= (`shouldSatisfy` (<= initialMaxStreamsBidi (scParameters sc)))
  where
    client = do
        waitS
        C.run cc $ \conn -> do
            _ <- Timeout.timeout 1500000 $ forever $ do
                strm <- stream conn
                sendStream strm "x"
            return ()
    server maxOpen = run sc $ \conn -> do
        openRef <- newIORef (0 :: Int)
        forM_ [0 :: Int ..] $ \n -> do
            strm <- acceptStream conn
            _ <- recvStream strm 1
            if n `mod` 10 == 0
                then closeStream strm
                else do
                    o <- atomicModifyIORef' openRef $ \x -> (x + 1, x + 1)
                    atomicModifyIORef' maxOpen $ \m -> (max m o, ())

-- | The server reads a byte of each request and closes the stream, the
--   client never sends a FIN.  What the server kept of each, to give back
--   the window late frames spend, stayed for as long as the connection did;
--   STOP_SENDING now has the client reset them, which settles them.
testDepartedForgotten :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testDepartedForgotten cc sc waitS = do
    left <- newEmptyMVar
    withAsync (server left) $ \_ -> do
        waitS
        C.run cc $ \conn -> do
            replicateM_ n $ do
                strm <- stream conn
                sendStream strm "x"
            takeMVar left `shouldReturn` 0
  where
    n = 300 :: Int
    server left = run sc $ \conn -> do
        replicateM_ n $ do
            strm <- acceptStream conn
            _ <- recvStream strm 1
            closeStream strm
        let departed = IntMap.size <$> readTVarIO (departedStreams conn)
            settle :: Int -> IO Int
            settle 0 = departed
            settle k = do
                d <- departed
                if d == 0 then return 0 else threadDelay 10000 >> settle (k - 1)
        settle 300 >>= putMVar left

-- | As above, but the client does not hear the STOP_SENDING.  The streams
--   it leaves unfinished are not given back to its limit, so the server
--   keeps no more of them than it allows open at once.
testDepartedBounded :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testDepartedBounded cc sc0 waitS = do
    most <- newIORef (0 :: Int)
    opened <- newIORef (0 :: Int)
    withAsync (server most) $ \_ -> do
        waitS
        C.run cc $ \conn -> do
            _ <- Timeout.timeout 1500000 $ forever $ do
                strm <- stream conn
                sendStream strm "x"
                atomicModifyIORef' opened $ \x -> (x + 1, ())
            return ()
        readIORef opened >>= (`shouldSatisfy` (<= limit))
        readIORef most >>= (`shouldSatisfy` (<= limit))
  where
    limit = initialMaxStreamsBidi $ scParameters sc0
    sc = sc0{scHooks = (scHooks sc0){onPlainCreated = hide}}
    hide _ plain = plain{plainFrames = map unstop $ plainFrames plain}
    unstop StopSending{} = Ping
    unstop f = f
    server most = run sc $ \conn -> forever $ do
        strm <- acceptStream conn
        _ <- recvStream strm 1
        closeStream strm
        d <- IntMap.size <$> readTVarIO (departedStreams conn)
        atomicModifyIORef' most $ \m -> (max m d, ())

-- | The server closes each stream as soon as it has read a byte, while the
--   client's FIN for it is on its way.  The FIN is the only thing that ends
--   the stream here: the server's STOP_SENDING is hidden.  Every stream is
--   to be forgotten, and given back to the client's limit, in the end.
--
-- Closing used to take the stream out of the table and keep what it owed
-- in two steps, and a frame handled in between was counted in neither.  The
-- window was a few microseconds and this does not hit it; it checks that
-- FINs crossing the close, now one transaction against it, still settle.
testFinCrossesClose :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testFinCrossesClose cc sc0 waitS = do
    left <- newEmptyMVar
    withAsync (server left) $ \_ -> do
        waitS
        r <- Timeout.timeout 20000000 $ C.run cc $ \conn -> do
            replicateM_ n $ do
                strm <- stream conn
                sendStream strm "x"
                shutdownStream strm
            takeMVar left
        r `shouldBe` Just 0
  where
    n = 2000 :: Int
    sc = sc0{scHooks = (scHooks sc0){onPlainCreated = hide}}
    hide _ plain = plain{plainFrames = map unstop $ plainFrames plain}
    unstop StopSending{} = Ping
    unstop f = f
    server left = run sc $ \conn -> do
        replicateM_ n $ do
            strm <- acceptStream conn
            _ <- recvStream strm 1
            closeStream strm
        let departed = IntMap.size <$> readTVarIO (departedStreams conn)
            settle :: Int -> IO Int
            settle 0 = departed
            settle k = do
                d <- departed
                if d == 0 then return 0 else threadDelay 10000 >> settle (k - 1)
        settle 300 >>= putMVar left

-- | The server closes the first unidirectional stream and keeps the rest.
-- The client may then have initial_max_streams_uni plus one.  The limit was
-- raised by initial_max_streams_bidi instead, 64 against 3.
testUniStreams :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testUniStreams cc sc waitS = do
    opened <- newIORef (0 :: Int)
    withAsync server $ \_ -> do
        client opened
        readIORef opened
            >>= (`shouldSatisfy` (<= initialMaxStreamsUni (scParameters sc) + 1))
  where
    client opened = do
        waitS
        C.run cc $ \conn -> do
            _ <- Timeout.timeout 1500000 $ forever $ do
                strm <- unidirectionalStream conn
                sendStream strm "x"
                modifyIORef' opened (+ 1)
            return ()
    server = run sc $ \conn -> do
        strm0 <- acceptStream conn
        _ <- recvStream strm0 1
        closeStream strm0
        forever $ do
            strm <- acceptStream conn
            recvStream strm 1

isResetStream :: Frame -> Bool
isResetStream ResetStream{} = True
isResetStream _ = False

-- | A unidirectional stream used to be checked against the counter of
--   bidirectional ones, so a client that had opened none of those closed the
--   connection with STREAM_STATE_ERROR on a STOP_SENDING for stream 2.
testStopClosedUni :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testStopClosedUni cc sc waitS = do
    closed <- newEmptyMVar
    stopped <- newEmptyMVar
    withAsync (server closed stopped) $ \_ -> client closed stopped
  where
    client closed stopped = do
        waitS
        C.run cc $ \conn -> do
            uni <- unidirectionalStream conn
            sendStream uni "x"
            closeStream uni
            putMVar closed ()
            () <- takeMVar stopped
            threadDelay 200000
            strm <- stream conn
            sendStream strm "ping"
            shutdownStream strm
            recvStream strm 4 `shouldReturn` "pong"
    server closed stopped = run sc $ \conn -> do
        uni <- acceptStream conn
        recvStream uni 1 `shouldReturn` "x"
        () <- takeMVar closed
        -- Sent as is: 'stopStream' sends nothing for a stream whose FIN
        -- has arrived, and a peer's may cross it.
        sendFrames
            conn
            RTT1Level
            [StopSending (streamId uni) $ ApplicationProtocolError 0]
        putMVar stopped ()
        strm <- acceptStream conn
        _ <- recvStream strm 4
        sendStream strm "pong"
        shutdownStream strm

testRecvStreamClientStopFirst
    :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testRecvStreamClientStopFirst cc sc waitS = do
    mvar <- newEmptyMVar
    withAsync (server mvar) $ \_ -> client mvar
  where
    aerr = ApplicationProtocolError 0

    client mvar = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            sendStream strm (BS.replicate 10000 0)
            takeMVar mvar `shouldReturn` ()
            stopStream strm aerr
            resetStream strm aerr
            takeMVar mvar `shouldReturn` ()
    server mvar = run sc $ \conn -> do
        strm <- acceptStream conn
        consumeBytes strm 10000 `shouldReturn` ()
        -- notify client to stop stream after all bytes are received.
        putMVar mvar ()
        -- verify that recvStream does not block
        assertEndOfStream strm
        putMVar mvar ()

testRecvStreamServerStopFirst
    :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testRecvStreamServerStopFirst cc sc waitS = do
    mvar <- newEmptyMVar
    withAsync (server mvar) $ \_ -> client mvar
  where
    aerr = ApplicationProtocolError 0

    client mvar = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            sendStream strm (BS.replicate 10000 0)
            takeMVar mvar `shouldReturn` ()
    server mvar = run sc $ \conn -> do
        strm <- acceptStream conn
        consumeBytes strm 10000 `shouldReturn` ()
        -- ask client to stop sending.
        stopStream strm aerr
        -- verify that recvStream does not block
        assertEndOfStream strm
        resetStream strm aerr
        putMVar mvar ()

testSendRecv :: C.ClientConfig -> ServerConfig -> IO () -> Int -> IO ()
testSendRecv cc sc waitS times = do
    mvar <- newEmptyMVar
    withAsync (server mvar) $ \_ -> client mvar
  where
    client mvar = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            let bs = BS.replicate 10000 0
            replicateM_ times $ sendStream strm bs
            shutdownStream strm
            takeMVar mvar `shouldReturn` ()
    server mvar = run sc $ \conn -> do
        strm <- acceptStream conn
        consumeBytes strm (10000 * times)
        assertEndOfStream strm
        putMVar mvar ()

-- | The client sends @times@ blocks and the server sends them back.
testEcho :: C.ClientConfig -> ServerConfig -> IO () -> Int -> IO ()
testEcho cc sc waitS times = do
    mvar <- newEmptyMVar
    withAsync (server mvar) $ \_ -> client mvar
  where
    len = 10000 * times
    client mvar = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            let bs = BS.replicate 10000 0
            replicateM_ times $ sendStream strm bs
            shutdownStream strm
            consumeBytes strm len
            assertEndOfStream strm
            putMVar mvar ()
    -- Until the client has it all: returning closes the connection, and
    -- the client was then now and then reset before it had read it.
    server mvar = run sc $ \conn -> do
        strm <- acceptStream conn
        consumeBytes strm len
        assertEndOfStream strm
        replicateM_ times $ sendStream strm $ BS.replicate 10000 0
        shutdownStream strm
        takeMVar mvar

-- | Exchanging data after the client has been sent a forged packet.  The
--   client is to run its action once, to the end.
testInjected
    :: C.ClientConfig
    -> ServerConfig
    -> IO ()
    -> (CID -> CID -> IO BS.ByteString)
    -> IO ()
testInjected cc sc waitS mk = do
    trigger <- newEmptyMVar
    runs <- newIORef (0 :: Int)
    mvar <- newEmptyMVar
    r <- Timeout.timeout 10_000_000 $
        withPipe (InjectToClient trigger mk) $
            withAsync (server mvar) $
                \_ -> client trigger runs mvar
    r `shouldBe` Just ()
    readIORef runs `shouldReturn` 1
  where
    client trigger runs mvar = do
        waitS
        C.run cc $ \conn -> do
            atomicModifyIORef' runs $ \n -> (n + 1, ())
            waitEstablished conn
            void $ tryPutMVar trigger ()
            threadDelay 100_000
            strm <- stream conn
            sendStream strm $ BS.replicate 10000 0
            shutdownStream strm
            takeMVar mvar
    server mvar = run sc $ \conn -> do
        strm <- acceptStream conn
        consumeBytes strm 10000
        assertEndOfStream strm
        putMVar mvar ()

-- | 'testSpuriousMigration', with the client's packet forwarded to the
--   server's IPv6 socket.
testSpuriousMigration6 :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testSpuriousMigration6 cc sc waitS = do
    paths <- newEmptyMVar
    trigger <- newEmptyMVar
    withPipe (ForwardAside6 trigger) $
        withAsync (pathEchoServer sc paths) $ \_ -> do
            waitS
            C.run cc $ \conn -> do
                strm <- stream conn
                echo strm "ping1" `shouldReturn` Just "ping1"
                original <- takeMVar paths
                putMVar trigger ()
                sendStream strm "ping2"
                Timeout.timeout 1500000 (recvStream strm 1024)
                    `shouldReturn` Just "ping2"
                _ <- takeMVar paths
                echo strm "ping3" `shouldReturn` Just "ping3"
                takeMVar paths `shouldReturn` original

-- | A stateless reset with the token the server gave.  The client's reader
--   threw 'ConnectionIsReset' to the connection's main thread; it now asks
--   the protocol threads to end with it.
testStatelessResetReceived :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testStatelessResetReceived cc sc waitS = do
    trigger <- newEmptyMVar
    tokenVar <- newEmptyMVar
    let mk _ _ = readMVar tokenVar >>= makeStatelessReset 64
    withPipe (InjectToClient trigger mk) $
        withAsync (run sc $ \_ -> threadDelay 5_000_000) $ \_ -> do
            waitS
            noUncaught $
                C.run cc (go trigger tokenVar) `shouldThrow` isReset
  where
    go trigger tokenVar conn = do
        waitEstablished conn
        mtoken <- statelessResetToken <$> getPeerParameters conn
        case mtoken of
            Nothing -> expectationFailure "no stateless_reset_token"
            Just token -> do
                putMVar tokenVar token
                putMVar trigger ()
                threadDelay 3_000_000
    isReset ConnectionIsReset = True
    isReset _ = False

-- | The server asks the client to stop sending on @n@ streams at once.
testStopMany :: C.ClientConfig -> ServerConfig -> IO () -> Int -> IO ()
testStopMany cc sc waitS n = do
    mvar <- newEmptyMVar
    ref <- newIORef 0
    r <- Timeout.timeout 10_000_000 $
        withPipe (DropServerPacket []) $
            withAsync (server mvar) $
                \_ -> client mvar >>= writeIORef ref
    r `shouldBe` Just ()
    readIORef ref `shouldReturn` n
  where
    client mvar = do
        waitS
        C.run cc $ \conn -> do
            strms <- replicateM n $ do
                strm <- stream conn
                sendStream strm "x"
                return strm
            () <- takeMVar mvar
            threadDelay 300_000
            rs <- forM strms $ \strm ->
                E.try (sendStream strm "y") :: IO (Either QUICException ())
            return $ length [() | Left _ <- rs]
    server mvar = run sc $ \conn -> do
        strms <- replicateM n $ acceptStream conn
        mapM_ (\strm -> stopStream strm $ ApplicationProtocolError 0) strms
        putMVar mvar ()
        threadDelay 1_000_000

testMultiSendRecv :: C.ClientConfig -> ServerConfig -> IO () -> Int -> IO ()
testMultiSendRecv cc sc waitS times = do
    mvars <- replicateM concurrency newEmptyMVar
    withAsync (server mvars) $ \_ -> client mvars
  where
    concurrency = 10
    chunklen = 12345
    chunk = BS.replicate chunklen 0
    client mvars = do
        waitS
        C.run cc $ \conn -> foldr1 concurrently_ $ replicate concurrency $ go conn
      where
        go conn = do
            strm <- stream conn
            let n = streamId strm `div` 4
            sendStream strm $ BS.singleton $ fromIntegral n
            replicateM_ times $ sendStream strm chunk
            shutdownStream strm
            takeMVar (mvars !! n) `shouldReturn` ()
    server mvars = run sc loop
      where
        loop conn = do
            strm <- acceptStream conn
            void $ forkIO $ do
                bs <- recvStream strm 1
                case BS.uncons bs of
                    Nothing -> return ()
                    Just (w, _) -> do
                        let n = fromIntegral w
                        consumeBytes strm (chunklen * times)
                        assertEndOfStream strm
                        putMVar (mvars !! n) ()
            loop conn

appErr :: QUICException -> Bool
appErr (ApplicationProtocolErrorIsReceived _ _) = True
appErr _ = False

testAbort :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testAbort cc sc waitS = do
    withAsync server $ \_ ->
        client `shouldThrow` appErr
  where
    client = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            sendStream strm "foo"
            void $ recvStream strm 10
    server = run sc loop
      where
        loop conn = do
            _strm <- acceptStream conn
            void $
                forkIO $
                    abortConnection
                        conn
                        (ApplicationProtocolError 1)
                        "testing abortConnection"
            loop conn

-- | RESET_STREAM ends the peer's sending part alone (RFC 9000, section 3.2).
--   What we have to send on a bidirectional stream must still go out.
testSendAfterReset :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testSendAfterReset cc sc waitS = do
    res <- newEmptyMVar
    withAsync (server res) $ \_ -> do
        client
        takeMVar res >>= (`shouldBe` True)
  where
    client = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            sendStream strm "ping"
            -- The reply says the "ping" has arrived, so that the
            -- RESET_STREAM cannot overtake it and be dropped as a frame
            -- for a stream that does not exist yet.
            _ <- recvStream strm 1024
            resetStream strm (ApplicationProtocolError 0)
            threadDelay 300000
    server res = run sc $ \conn -> do
        strm <- acceptStream conn
        _ <- recvStream strm 1024
        sendStream strm "ack"
        -- An empty ByteString: the pseudo FIN that the RESET_STREAM left.
        let recvEOF = do
                bs <- recvStream strm 1024
                unless (bs == "") recvEOF
        recvEOF
        sent <-
            (True <$ sendStream strm "pong") `E.catch` \e -> case e of
                StreamIsClosed -> return False
                _ -> E.throwIO e
        putMVar res sent

-- | STOP_SENDING makes us reset our sending part (RFC 9000, section 3.5),
--   so nothing more may go out on it.
testStopSending :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testStopSending cc sc waitS =
    withAsync server $ \_ -> client
  where
    client = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            sendStream strm "ping"
            stopped <-
                ( do
                    _ <- Timeout.timeout 2000000 $ forever $ do
                        threadDelay 20000
                        sendStream strm "x"
                    return False
                )
                    `E.catch` \e -> case e of
                        StreamIsClosed -> return True
                        _ -> E.throwIO e
            stopped `shouldBe` True
    server = run sc $ \conn -> do
        strm <- acceptStream conn
        _ <- recvStream strm 1024
        stopStream strm (ApplicationProtocolError 0)
        threadDelay 3000000

-- | 'resetStream' leaves nothing to wait for.  An application that resets a
--   stream because 'sendStream' failed does so with the sending part closed
--   by the peer's STOP_SENDING already, and 'recvStream' has to end there
--   rather than block: what the peer sends afterwards is dropped anyway,
--   the stream being out of the table.
testRecvAfterReset :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testRecvAfterReset cc sc waitS =
    withAsync server $ \_ -> client
  where
    client = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            sendStream strm "ping"
            _ <-
                ( do
                    _ <- Timeout.timeout 2000000 $ forever $ do
                        threadDelay 20000
                        sendStream strm "x"
                    return ()
                )
                    `E.catch` \e -> case e of
                        StreamIsClosed -> return ()
                        _ -> E.throwIO e
            resetStream strm (ApplicationProtocolError 0)
            mbs <- Timeout.timeout 1000000 $ recvStream strm 1024
            mbs `shouldBe` Just ""
    server = run sc $ \conn -> do
        strm <- acceptStream conn
        _ <- recvStream strm 1024
        stopStream strm (ApplicationProtocolError 0)
        threadDelay 3000000

-- | RFC 9000, section 3.2: the receiving part of a stream the peer opened is
--   created when the first STREAM, STREAM_DATA_BLOCKED or RESET_STREAM frame
--   for it arrives.  Here the client never sends on the stream, so the
--   RESET_STREAM is the first the server hears of it.
testResetOnly :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testResetOnly cc sc waitS = do
    got <- newEmptyMVar
    withAsync (server got) $ \_ -> do
        client
        -- With a timeout: without the stream, 'acceptStream' on the server
        -- never returns, and the test would hang rather than fail.
        r <- Timeout.timeout 1000000 $ takeMVar got
        r `shouldBe` Just (Just aerr)
  where
    aerr = ApplicationProtocolError 7
    client = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            resetStream strm aerr
            threadDelay 300000
    server got = run sc $ \conn -> do
        strm <- acceptStream conn
        bs <- recvStream strm 1024
        bs `shouldBe` ""
        resetReceived strm >>= putMVar got

-- | The same, for the reset that follows data on the stream.  It overtakes
--   the data: the sender empties the queue the RESET_STREAM is on before the
--   one the STREAM frame is on.
testResetOvertakes :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testResetOvertakes cc sc waitS = do
    got <- newEmptyMVar
    withAsync (server got) $ \_ -> do
        client
        -- With a timeout: without the stream, 'acceptStream' on the server
        -- never returns, and the test would hang rather than fail.
        r <- Timeout.timeout 1000000 $ takeMVar got
        r `shouldBe` Just (Just aerr)
  where
    aerr = ApplicationProtocolError 7
    client = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            sendStream strm "ping"
            resetStream strm aerr
            threadDelay 300000
    server got = run sc $ \conn -> do
        strm <- acceptStream conn
        let recvEOF = do
                bs <- recvStream strm 1024
                unless (bs == "") recvEOF
        recvEOF
        resetReceived strm >>= putMVar got

-- | RFC 9000, section 3.2 again, for the other frame of the three: a
--   STREAM_DATA_BLOCKED opens the stream it names as well.
testDataBlockedOpens :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testDataBlockedOpens cc0 sc waitS = do
    got <- newEmptyMVar
    withAsync (server got) $ \_ -> do
        client
        r <- Timeout.timeout 1000000 $ takeMVar got
        r `shouldBe` Just 0
  where
    cc = cc0{ccHooks = (ccHooks cc0){onPlainCreated = blockedOnStream0}}
    blockedOnStream0 lvl plain
        | lvl == RTT1Level =
            plain{plainFrames = StreamDataBlocked 0 0 : plainFrames plain}
        | otherwise = plain
    client = do
        waitS
        -- No stream of its own: the frame above is all the server hears of
        -- stream 0.
        C.run cc $ \_conn -> threadDelay 300000
    server got = run sc $ \conn -> do
        strm <- acceptStream conn
        putMVar got $ streamId strm

-- | RFC 9000, section 4.5: where a stream ends, once said, cannot be said
--   differently, and nothing may arrive past it.  The frames go in by a hook,
--   since a well-behaved client sends none of these.
testFinalSize
    :: C.ClientConfig -> ServerConfig -> IO () -> [Frame] -> IO ()
testFinalSize cc0 sc waitS frames =
    withAsync quietServer $ \_ -> client `shouldThrow` finalSizeError
  where
    quietServer = run sc $ \conn -> forever $ void $ acceptStream conn
    cc = cc0{ccHooks = (ccHooks cc0){onPlainCreated = inject}}
    inject lvl plain
        | lvl == RTT1Level = plain{plainFrames = frames ++ plainFrames plain}
        | otherwise = plain
    client = do
        waitS
        C.run cc $ \_conn -> threadDelay 1000000

finalSizeError :: QUICException -> Bool
finalSizeError (TransportErrorIsReceived FinalSizeError _) = True
finalSizeError _ = False

flowControlError :: QUICException -> Bool
flowControlError (TransportErrorIsReceived FlowControlError _) = True
flowControlError _ = False

-- | RFC 9000, section 4.5: "A receiver SHOULD use the final size to account
--   for all bytes sent on the stream in its connection-level flow
--   controller."  A hundred thousand octets is well past what this server
--   allows for the whole connection, so a stream reset at that final size,
--   none of which arrives, is over the limit and should be answered as one.
--
-- Uncounted, as it was, it cost the peer nothing at all: the window we
-- advertise fell behind what the peer believed it had spent, by the tail of
-- every stream it reset, and nothing here noticed.
testResetCountsAgainstTheWindow
    :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testResetCountsAgainstTheWindow cc0 sc0 waitS =
    withAsync quietServer $ \_ -> client `shouldThrow` flowControlError
  where
    sc = sc0{scParameters = (scParameters sc0){initialMaxData = 1000}}
    quietServer = run sc $ \conn -> forever $ void $ acceptStream conn
    cc = cc0{ccHooks = (ccHooks cc0){onPlainCreated = inject}}
    inject lvl plain
        | lvl == RTT1Level =
            plain
                { plainFrames =
                    ResetStream 0 (ApplicationProtocolError 0) 100000 : plainFrames plain
                }
        | otherwise = plain
    client = do
        waitS
        C.run cc $ \_conn -> threadDelay 1000000

-- | RFC 9000, section 4.5: the final size counts against the stream's
--   limit as well as the connection's.  Only the connection's was checked,
--   so a reset could claim far more than the stream was ever allowed.
testResetOverStreamLimit :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testResetOverStreamLimit cc0 sc0 waitS =
    withAsync quietServer $ \_ -> client `shouldThrow` flowControlError
  where
    sc =
        sc0
            { scParameters =
                (scParameters sc0)
                    { initialMaxData = 1000000
                    , initialMaxStreamDataBidiRemote = 1000
                    }
            }
    quietServer = run sc $ \conn -> forever $ void $ acceptStream conn
    cc = cc0{ccHooks = (ccHooks cc0){onPlainCreated = inject}}
    inject lvl plain
        | lvl == RTT1Level =
            plain
                { plainFrames =
                    ResetStream 0 (ApplicationProtocolError 0) 5000 : plainFrames plain
                }
        | otherwise = plain
    client = do
        waitS
        C.run cc $ \_conn -> threadDelay 1000000

-- | RFC 9000, section 4.1: what the peer has spent is the largest offset
--   it has sent on each stream, gaps and all.  One octet at offset five
--   thousand spends five thousand and one, well past this server's thousand;
--   only the one octet was counted.
testGapCountsAgainstTheWindow
    :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testGapCountsAgainstTheWindow cc0 sc0 waitS =
    withAsync quietServer $ \_ -> client `shouldThrow` flowControlError
  where
    sc = sc0{scParameters = (scParameters sc0){initialMaxData = 1000}}
    quietServer = run sc $ \conn -> forever $ void $ acceptStream conn
    cc = cc0{ccHooks = (ccHooks cc0){onPlainCreated = inject}}
    inject lvl plain
        | lvl == RTT1Level =
            plain{plainFrames = StreamF 0 5000 ["x"] False : plainFrames plain}
        | otherwise = plain
    client = do
        waitS
        C.run cc $ \_conn -> threadDelay 1000000

-- | A stream the application has closed, and the peer has not finished, is
--   still held to the limits it was sent under: here a frame for it goes
--   past the limit given as (connection, stream).  Nothing was checked for
--   such a frame.  The server's STOP_SENDING is hidden, so that the client
--   does not reset the stream and end it.
testDepartedOverLimit
    :: (Int, Int) -> C.ClientConfig -> ServerConfig -> IO () -> IO ()
testDepartedOverLimit (connLim, strmLim) cc0 sc0 waitS =
    withAsync server $ \_ -> client `shouldThrow` flowControlError
  where
    sc =
        sc0
            { scParameters =
                (scParameters sc0)
                    { initialMaxData = connLim
                    , initialMaxStreamDataBidiRemote = strmLim
                    }
            , scHooks = (scHooks sc0){onPlainCreated = hide}
            }
    hide _ plain = plain{plainFrames = map unstop $ plainFrames plain}
    unstop StopSending{} = Ping
    unstop f = f
    server = run sc $ \conn -> forever $ do
        strm <- acceptStream conn
        _ <- recvStream strm 1
        closeStream strm
    -- One octet at offset 5000 of stream 0, past whichever limit is the
    -- smaller, along with the data of stream 4, which goes out only once
    -- the server has closed stream 0.
    cc = cc0{ccHooks = (ccHooks cc0){onPlainCreated = inject}}
    inject lvl plain
        | lvl == RTT1Level && any onStream4 (plainFrames plain) =
            plain{plainFrames = StreamF 0 5000 ["x"] False : plainFrames plain}
        | otherwise = plain
    onStream4 (StreamF 4 _ _ _) = True
    onStream4 _ = False
    client = do
        waitS
        C.run cc $ \conn -> do
            s0 <- stream conn
            sendStream s0 "x"
            threadDelay 300000
            s1 <- stream conn
            sendStream s1 "y"
            threadDelay 1000000

-- | RFC 9000, section 10.2: an endpoint that ends a connection sends
--   CONNECTION_CLOSE.  Anything thrown in here that is not already on its way
--   to the peer used to end the connection in silence, leaving the peer to
--   wait out its own idle timeout.
testServerThrows :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testServerThrows cc sc waitS =
    withAsync server $ \_ -> client `shouldThrow` internalError
  where
    server = run sc $ \_conn -> E.throwIO $ userError "the application gave up"
    client = do
        waitS
        C.run cc $ \conn -> do
            strm <- stream conn
            sendStream strm "ping"
            void $ recvStream strm 1024

internalError :: QUICException -> Bool
internalError (TransportErrorIsReceived InternalError _) = True
internalError _ = False

-- | The peer hears of a transport error at once, however long the
--   application takes to unwind.
--
-- The protocol threads and the application run under one 'concurrently_',
-- which cancels the application when they fail and then waits for it, under
-- 'uninterruptibleMask_'.  Said after that, the CONNECTION_CLOSE waits with
-- it, and a peer told nothing waits out its own idle timeout.  Here the
-- application sits for three seconds after it is cancelled and the client
-- allows one and a half.
testSlowApp :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testSlowApp cc0 sc waitS =
    withAsync server $ \_ -> client `shouldThrow` frameEncodingError
  where
    server = run sc $ \conn ->
        forever (void $ acceptStream conn) `E.catch` \(e :: E.SomeException) -> do
            threadDelay 3000000
            E.throwIO e
    cc = cc0{ccHooks = (ccHooks cc0){onPlainCreated = inject}}
    inject lvl plain
        | lvl == RTT1Level =
            plain
                { plainFrames = MaxStreams Bidirectional (2 ^ (61 :: Int)) : plainFrames plain
                }
        | otherwise = plain
    client = do
        waitS
        C.run cc $ \_conn -> threadDelay 1500000

-- | Running an action and failing if any thread let an exception go
--   uncaught meanwhile.
--
-- Stopping a server told each connection to close by throwing to its main
-- thread.  'testSlowApp' stops the server while its connection waits for an
-- application that is slow to unwind, and the exception arrived in the
-- teardown, where nothing caught it: the runtime reported an uncaught
-- 'Abort' every time.
noUncaught :: IO () -> IO ()
noUncaught act = do
    caught <- newIORef []
    old <- getUncaughtExceptionHandler
    setUncaughtExceptionHandler $ \e ->
        atomicModifyIORef' caught $ \es -> (show e : es, ())
    act `E.finally` setUncaughtExceptionHandler old
    readIORef caught `shouldReturn` []

frameEncodingError :: QUICException -> Bool
frameEncodingError (TransportErrorIsReceived FrameEncodingError _) = True
frameEncodingError _ = False

-- | A server that answers without reading the body still gives the octets
--   back to the connection's window.
--
-- They were counted as received and, read by nobody, were never counted as
-- consumed, so the window we advertise stayed that much smaller for the rest
-- of the connection.  Here twenty streams of four kilobytes go to a server
-- that reads one octet of each, against a window of thirty-two: uncounted,
-- the client is blocked before it is halfway through.
-- | The octets that arrive for a stream after the application has closed
--   it are given back to the connection's window too.
--
-- They go nowhere -- the stream is gone from the table and the data is
-- dropped -- but the peer spent its connection window on them all the same.
-- Counted by nobody, the window we advertise falls that much behind what
-- the peer believes it has spent, for the rest of the connection.
--
-- The stream is written in two halves with a pause between them, so that the
-- server reads its one octet and closes while the second half is still on
-- its way.  Without the pause this is a race the server usually loses --
-- which is why 'testCloseWithoutReading' passed on one machine and failed on
-- a slower one.
testCloseWhileArriving :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testCloseWhileArriving cc sc0 waitS =
    withAsync server $ \_ -> client
  where
    sc = sc0{scParameters = (scParameters sc0){initialMaxData = 32768}}
    server = run sc $ \conn -> forever $ do
        strm <- acceptStream conn
        _ <- recvStream strm 1
        closeStream strm
    client = do
        waitS
        r <- Timeout.timeout 5000000 $ C.run cc $ \conn ->
            replicateM_ 20 $ do
                strm <- stream conn
                sendStream strm $ BS.replicate 2048 0
                threadDelay 2000
                -- The server's STOP_SENDING may have reset the stream by now.
                E.handle stopped $ do
                    sendStream strm $ BS.replicate 2048 0
                    shutdownStream strm
                closeStream strm
        r `shouldBe` Just ()

    stopped StreamIsClosed = return ()
    stopped e = E.throwIO e

testCloseWithoutReading :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testCloseWithoutReading cc sc0 waitS =
    withAsync server $ \_ -> client
  where
    sc = sc0{scParameters = (scParameters sc0){initialMaxData = 32768}}
    server = run sc $ \conn -> forever $ do
        strm <- acceptStream conn
        _ <- recvStream strm 1
        closeStream strm
    client = do
        waitS
        r <- Timeout.timeout 5000000 $ C.run cc $ \conn ->
            replicateM_ 20 $ do
                strm <- stream conn
                -- The server's STOP_SENDING may reset the stream meanwhile.
                E.handle stopped $ do
                    sendStream strm $ BS.replicate 4096 0
                    shutdownStream strm
                closeStream strm
        r `shouldBe` Just ()
    stopped StreamIsClosed = return ()
    stopped e = E.throwIO e

-- | Only the closer closed the client's socket, and a connection the peer
--   ends has none: the socket was left open.
testSocketClosed :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testSocketClosed cc sc waitS = do
    ref <- newIORef Nothing
    withAsync server $ \_ -> do
        waitS
        r <- E.try $ C.run cc $ \conn -> do
            getSocket conn >>= writeIORef ref . Just
            strm <- stream conn
            sendStream strm "ping"
            void $ recvStream strm 1024
        case r of
            Left (ApplicationProtocolErrorIsReceived _ _) -> return ()
            _ -> expectationFailure $ show r
        msock <- readIORef ref
        case msock of
            Nothing -> expectationFailure "no socket"
            Just sock -> NS.withFdSocket sock return `shouldReturn` (-1)
  where
    server = run sc $ \conn -> do
        strm <- acceptStream conn
        _ <- recvStream strm 1024
        abortConnection conn (ApplicationProtocolError 1) "bye"

-- | The server answers a "ping" and returns, which closes the connection
--   with NO_ERROR.  A client waiting on the server then gets
--   'ConnectionIsClosed' at once rather than at the idle timeout, and one
--   not waiting returns what it returns.  'Nothing' expects the former.
--   Either way, the client's socket is closed.
testPeerClosed
    :: C.ClientConfig
    -> ServerConfig
    -> IO ()
    -> Maybe BS.ByteString
    -> (Connection -> IO BS.ByteString)
    -> IO ()
testPeerClosed cc sc waitS expected body = do
    done <- newEmptyMVar
    ref <- newIORef Nothing
    withAsync (server done) $ \_ -> do
        waitS
        r <- Timeout.timeout 3000000 $ E.try $ C.run cc $ \conn -> do
            getSocket conn >>= writeIORef ref . Just
            body conn
        case r of
            Nothing -> expectationFailure "the client waited for the idle timeout"
            Just (Left e) -> case (e, expected) of
                (ConnectionIsClosed _, Nothing) -> return ()
                _ -> expectationFailure $ show e
            Just (Right bs) -> Just bs `shouldBe` expected
        msock <- readIORef ref
        case msock of
            Nothing -> expectationFailure "no socket"
            Just sock -> NS.withFdSocket sock return `shouldReturn` (-1)
        takeMVar done
  where
    server done = run sc $ \conn -> do
        strm <- acceptStream conn
        _ <- recvStream strm 1024
        sendStream strm "pong"
        putMVar done ()

-- | Sending the server a short header packet of each size for a connection
--   it does not know, and the size of the stateless reset it answers with.
resetSizes :: [Int] -> IO [Maybe Int]
resetSizes lens = do
    addr : _ <-
        NS.getAddrInfo
            (Just NS.defaultHints{NS.addrSocketType = NS.Datagram})
            (Just "127.0.0.1")
            (Just "15003")
    E.bracket (NS.openSocket addr) NS.close $ \s -> forM lens $ \len -> do
        _ <-
            NSB.sendTo s (BS.cons 0x40 $ BS.replicate (len - 1) 0x11) $ NS.addrAddress addr
        fmap (BS.length . fst) <$> Timeout.timeout 1000000 (NSB.recvFrom s 2048)

-- | A server that echoes, and tells after each echo where it sent it.
pathEchoServer :: ServerConfig -> MVar NS.SockAddr -> IO ()
pathEchoServer sc paths = run sc $ \conn -> do
    strm <- acceptStream conn
    let loop = do
            bs <- recvStream strm 1024
            unless (bs == "") $ do
                sendStream strm bs
                peerSockAddr <$> getPathInfo conn >>= putMVar paths
                loop
    loop

echo :: Stream -> BS.ByteString -> IO (Maybe BS.ByteString)
echo strm bs = do
    sendStream strm bs
    Timeout.timeout 2000000 $ recvStream strm 1024

-- | RFC 9000 Sec 9.3: only a packet that decrypts moves the peer.  The
--   server took a new address from any packet with its CID on it, before
--   decrypting it, and sent everything there from then on.
testForgedPath
    :: C.ClientConfig
    -> ServerConfig
    -> IO ()
    -> (Version -> CID -> BS.ByteString)
    -> IO ()
testForgedPath cc sc waitS forge = do
    paths <- newEmptyMVar
    withPipe (DropClientPacket []) $
        withAsync (pathEchoServer sc paths) $ \_ -> do
            waitS
            C.run cc $ \conn -> do
                strm <- stream conn
                echo strm "ping1" `shouldReturn` Just "ping1"
                original <- takeMVar paths
                ver <- getVersion conn
                dcid <- getPeerCID conn
                addr : _ <-
                    NS.getAddrInfo
                        (Just NS.defaultHints{NS.addrSocketType = NS.Datagram})
                        (Just "127.0.0.1")
                        (Just "15003")
                E.bracket (NS.openSocket addr) NS.close $ \s ->
                    void $ NSB.sendTo s (forge ver dcid) $ NS.addrAddress addr
                threadDelay 300000
                echo strm "ping2" `shouldReturn` Just "ping2"
                takeMVar paths `shouldReturn` original

-- | A client that moves to a new port is still followed, now that the move
--   is taken from decrypted packets.
testRebindPath :: C.ClientConfig -> ServerConfig -> IO () -> IO ()
testRebindPath cc sc waitS = do
    paths <- newEmptyMVar
    -- Straight to the server: the relay would drop the new port.
    let cc' = cc{C.ccPortName = "15003"}
    withAsync (pathEchoServer sc paths) $ \_ -> do
        waitS
        C.run cc' $ \conn -> do
            strm <- stream conn
            echo strm "ping1" `shouldReturn` Just "ping1"
            original <- takeMVar paths
            void $ controlConnection conn NATRebinding
            -- The first echo may still go out on the old path, while the
            -- new one is being validated.
            let untilMoved (0 :: Int) = expectationFailure "the server never moved"
                untilMoved n = do
                    echo strm "ping" `shouldReturn` Just "ping"
                    p <- takeMVar paths
                    when (p == original) $ do
                        threadDelay 100000
                        untilMoved (n - 1)
            untilMoved 20

-- | RFC 9000 Sec 9.3.2: a packet of the client's, forwarded from another
--   address, moves the server there, and the validation of that address
--   fails.  The server waited for the PATH_RESPONSE for ever and went on
--   sending to the address that never answered.  Then it waited for the
--   validation to time out (about 3 s), though the client's next packets
--   came from the old address; they now send it back at once.
testSpuriousMigration :: C.ClientConfig -> ServerConfig -> IO () -> Int -> IO ()
testSpuriousMigration cc sc waitS within = do
    paths <- newEmptyMVar
    trigger <- newEmptyMVar
    withPipe (ForwardAside trigger) $
        withAsync (pathEchoServer sc paths) $ \_ -> do
            waitS
            C.run cc $ \conn -> do
                strm <- stream conn
                echo strm "ping1" `shouldReturn` Just "ping1"
                original <- takeMVar paths
                putMVar trigger ()
                -- Answered on the spurious path, and so not heard until
                -- the server is back on the old one.
                sendStream strm "ping2"
                Timeout.timeout within (recvStream strm 1024)
                    `shouldReturn` Just "ping2"
                _ <- takeMVar paths
                echo strm "ping3" `shouldReturn` Just "ping3"
                takeMVar paths `shouldReturn` original
