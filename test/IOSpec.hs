{-# LANGUAGE OverloadedStrings #-}

module IOSpec where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import Control.Monad
import qualified Data.ByteString as BS
import Data.IORef
import qualified System.Timeout as Timeout
import Test.Hspec

import Network.QUIC
import qualified Network.QUIC.Client as C
import Network.QUIC.Internal
import Network.QUIC.Server

import Config

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
        it "tells a stream that was reset from one that ended" $ do
            withPipe (DropClientPacket []) $ testResetReceived cc sc waitS
    describe "closed stream" $ do
        it "ignores a late copy of the data it received on a stream it opened" $ do
            withPipe (DelayServerPacket 300) $ testLateCopy False cc sc waitS
        it "ignores a late copy of the data it received on a stream the peer opened" $ do
            withPipe (DelayClientPacket 300) $ testLateCopy True cc sc waitS
    describe "stream limits" $ do
        it "keeps the peer's open bidirectional streams within the limit" $ do
            withPipe (DropClientPacket []) $ testOpenStreams cc sc waitS
        it "raises the limit on unidirectional streams by their own number" $ do
            withPipe (DropClientPacket []) $ testUniStreams cc sc waitS
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
    describe "port handover" $ do
        it "ignores a leftover datagram from the connection that just closed" $
            withPipeStray (Randomly 20) $
                testSendRecv cc sc waitS 20
    describe "concurrency" $ do
        it "can handle multiple clients" $ do
            withPipe (Randomly 20) $ testMultiSendRecv cc sc waitS 500
    describe "abortConnection" $ do
        it "can abort connection" $ do
            withPipe (Randomly 20) $ testAbort cc sc waitS

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
