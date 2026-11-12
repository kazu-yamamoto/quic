{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as BS
import Network.Control

import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Stream
import Network.QUIC.Types

-- | Creating a bidirectional stream.
stream :: Connection -> IO Stream
stream conn = do
    -- FLOW CONTROL: MAX_STREAMS: send: respecting peer's limit
    sid <- waitMyNewStreamId conn
    addStream conn sid

-- | Creating a unidirectional stream.
unidirectionalStream :: Connection -> IO Stream
unidirectionalStream conn = do
    -- FLOW CONTROL: MAX_STREAMS: send: respecting peer's limit
    sid <- waitMyNewUniStreamId conn
    addStream conn sid

-- | Sending data in the stream.
sendStream :: Stream -> ByteString -> IO ()
sendStream s dat = sendStreamMany s [dat]

----------------------------------------------------------------

data Blocked
    = BothBlocked Stream Int Int
    | ConnBlocked Int
    | StrmBlocked Stream Int
    deriving (Show)

-- | Counting and queueing at once, so that the offset given is the
--   stream's next one and the queue holds a stream's data in order.
queueTx :: Connection -> Stream -> [StreamData] -> Int -> STM ()
queueTx conn s dats len = do
    off <- addTxStreamData s len
    addTxData conn len
    putSendStreamQSTM conn $ TxStreamData s off dats len False

-- | Queueing the FIN, at the offset the stream has reached.
queueFin :: Stream -> IO ()
queueFin s = atomically $ do
    off <- addTxStreamData s 0
    putSendStreamQSTM (streamConnection s) $ TxStreamData s off [] 0 True

-- | Sending a list of data in the stream.
sendStreamMany :: Stream -> [ByteString] -> IO ()
sendStreamMany _ [] = return ()
sendStreamMany s dats0 = do
    sclosed <- isTxStreamClosed s
    when sclosed $ E.throwIO StreamIsClosed
    flowControl dats0 (totalLen dats0) False
  where
    conn = streamConnection s
    -- 0-RTT goes through here too.  It used to take the other road: the
    -- data went straight onto the queue and the window was told about it
    -- afterwards, so a resuming client spent a connection window it had not
    -- been given, and a server that counts answers that with
    -- FLOW_CONTROL_ERROR.  RFC 9000 Sec 7.4.1 holds a client sending 0-RTT
    -- to the limits the previous connection gave, and those are in the
    -- peer's parameters by the time anything is sent, so one check serves
    -- both.
    flowControl dats len wait = do
        -- FLOW CONTROL: MAX_STREAM_DATA: send: respecting peer's limit
        -- FLOW CONTROL: MAX_DATA: send: respecting peer's limit
        -- The window is taken in the transaction that finds it.  Two
        -- streams sending at once used to see the same window and send it
        -- twice over.
        eblocked <- atomically $ do
            r <- checkBlocked s len wait
            case r of
                Right n -> do
                    let (dats1, dats2)
                            | len == n = (dats, [])
                            | otherwise = split n dats
                    queueTx conn s dats1 n
                    return $ Right (n, dats2)
                Left blocked -> return $ Left blocked
        case eblocked of
            Right (n, dats2) ->
                when (n < len) $ flowControl dats2 (len - n) False
            Left blocked -> do
                -- Read each time round rather than once: the handshake may
                -- finish while we are waiting for the window, and a BLOCKED
                -- frame at a level we have no keys for goes nowhere.
                ready <- isConnection1RTTReady conn
                let lvl
                        | ready = RTT1Level
                        | otherwise = RTT0Level
                sendBlocked conn lvl blocked
                flowControl dats len True

sendBlocked :: Connection -> EncryptionLevel -> Blocked -> IO ()
sendBlocked conn lvl blocked = sendFrames conn lvl frames
  where
    frames = case blocked of
        StrmBlocked strm n -> [StreamDataBlocked (streamId strm) n]
        ConnBlocked n -> [DataBlocked n]
        BothBlocked strm n m -> [StreamDataBlocked (streamId strm) n, DataBlocked m]

split :: Int -> [BS.ByteString] -> ([BS.ByteString], [BS.ByteString])
split n0 dats0 = loop n0 dats0 id
  where
    loop 0 bss build = (build [], bss)
    loop _ [] build = (build [], [])
    loop n (bs : bss) build = case len `compare` n of
        GT ->
            let (bs1, bs2) = BS.splitAt n bs
             in (build [bs1], bs2 : bss)
        EQ -> (build [bs], bss)
        LT -> loop (n - len) bss (build . (bs :))
      where
        len = BS.length bs

checkBlocked :: Stream -> Int -> Bool -> STM (Either Blocked Int)
checkBlocked s len wait = do
    let conn = streamConnection s
    checkPeerClosedSTM conn
    strmFlow <- readStreamFlowTx s
    connFlow <- readConnectionFlowTx conn
    let strmWindow = txWindowSize strmFlow
        connWindow = txWindowSize connFlow
        minFlow = min strmWindow connWindow
        n = min len minFlow
    when wait $ check (n > 0)
    if n > 0
        then return $ Right n
        else do
            let cs = len > strmWindow
                cw = len > connWindow
                blocked
                    | cs && cw = BothBlocked s (txfLimit strmFlow) (txfLimit connFlow)
                    | cs = StrmBlocked s (txfLimit strmFlow)
                    | otherwise = ConnBlocked (txfLimit connFlow)
            return $ Left blocked

----------------------------------------------------------------

-- | Sending FIN in a stream.
--   'closeStream' should be called later.
shutdownStream :: Stream -> IO ()
shutdownStream s = do
    sclosed <- isTxStreamClosed s
    when sclosed $ E.throwIO StreamIsClosed
    setTxStreamClosed s
    queueFin s
    waitFinTx s

-- | Closing a stream without an error.
--   This sends FIN if necessary.
--   If the peer has not finished sending on it, this also sends
--   STOP_SENDING with error code 0; see 'closeStreamWith'.
closeStream :: Stream -> IO ()
closeStream s = closeStreamWith s $ ApplicationProtocolError 0

-- | 'closeStream' with the error code of the STOP_SENDING sent if the
--   peer has not finished sending on the stream.  HTTP\/3, for one, wants
--   H3_NO_ERROR there (RFC 9114, section 4.1).
closeStreamWith :: Stream -> ApplicationProtocolError -> IO ()
closeStreamWith s aerr = do
    let conn = streamConnection s
        sid = streamId s
        -- A unidirectional stream of the peer's has no sending side here.
        -- Sending a FIN on it anyway made the peer close the connection with
        -- STREAM_STATE_ERROR, so that one could not be closed at all.
        receiveOnly =
            (isClient conn && isServerInitiatedUnidirectional sid)
                || (isServer conn && isClientInitiatedUnidirectional sid)
    closed <- (||) <$> isConnectionClosed conn <*> isPeerClosed conn
    sclosed <- isTxStreamClosed s
    unless (receiveOnly || closed || sclosed) $ do
        setTxStreamClosed s
        queueFin s
        waitFinTx s
    stopUnfinished s aerr
    -- Outside the guard above: whether or not the FIN goes out, we are done
    -- with the stream, and 'recvStream' has to say so rather than block.
    setRxStreamClosed s
    releaseStream s

-- | Asking the peer to stop sending on a stream we are done with, if it has
--   not said where the stream ends.  It then resets the stream, and what we
--   keep of it ('departStream') is settled and dropped.
stopUnfinished :: Stream -> ApplicationProtocolError -> IO ()
stopUnfinished s aerr = do
    let conn = streamConnection s
        sid = streamId s
        sendOnly =
            (isClient conn && isClientInitiatedUnidirectional sid)
                || (isServer conn && isServerInitiatedUnidirectional sid)
    closed <- (||) <$> isConnectionClosed conn <*> isPeerClosed conn
    final <- rxFinal <$> getRxBounds s
    unless (sendOnly || closed || isJust final) $ stopStream s aerr

-- | Taking the stream out of the table and counting it as done with, once.
--
-- Only when the application is done with it: closing it or resetting it.  A
-- RESET_STREAM from the peer takes the stream out of the table, but whatever
-- is serving it may be at work yet, and counting it then would let a peer
-- that opens streams and resets them straight away have any number served
-- at once.
--
-- A stream of the peer's goes back to its limit on streams only once the
-- peer has finished it too.  Until then the peer may still send on it and
-- we keep what it owes; given back at once, a peer that never finishes its
-- streams could have us keep any number of them.
releaseStream :: Stream -> IO ()
releaseStream s = do
    first <- markReleased s
    when first $ do
        -- FLOW CONTROL: MAX_DATA: recv: what the connection counted as
        -- received for this stream and the application will never read:
        -- a request body a server answers without reading, say, or what
        -- never arrived of a stream whose end is known.  Left uncounted, the
        -- window we advertise stays that much smaller for the rest of the
        -- connection, and enough of them leave the peer blocked by octets
        -- nobody is waiting for.  Where the peer has not said where the
        -- stream ends, what arrives from here on is owed by what is kept.
        (owed, kept) <- departStream conn s
        when (owed > 0) $ do
            mx <- updateFlowRx conn owed
            case mx of
                Nothing -> return ()
                Just newMax -> do
                    sendFrames conn RTT1Level [MaxData newMax]
                    fire conn (Microseconds 50000) $
                        sendFrames conn RTT1Level [MaxData newMax]
        -- FLOW CONTROL: MAX_STREAMS: recv: announcing my limit properly
        unless kept $ releasePeerStream conn $ streamId s
  where
    conn = streamConnection s

-- | Accepting a stream initiated by the peer.
acceptStream :: Connection -> IO Stream
acceptStream conn = do
    InpStream s <- takeInput conn
    return s

-- | Receiving data in the stream. In the case where a FIN is received
--   an empty bytestring is returned.
recvStream
    :: Stream
    -> Int
    -- ^ Number of bytes to receive. In certain cases, `recvStream` can return
    -- fewer bytes than requested, but never more bytes than requested..
    -> IO ByteString
recvStream s n = do
    bs <- takeRecvStreamQwithSize s n
    let len = BS.length bs
        sid = streamId s
        conn = streamConnection s
    -- FLOW CONTROL: MAX_STREAM_DATA: recv: announcing my limit properly
    mxs <- updateStreamFlowRx s len
    case mxs of
        Nothing -> return ()
        Just newMax -> do
            sendFrames conn RTT1Level [MaxStreamData sid newMax]
            fire conn (Microseconds 50000) $
                sendFrames conn RTT1Level [MaxStreamData sid newMax]
    -- FLOW CONTROL: MAX_DATA: recv: announcing my limit properly
    mxc <- updateFlowRx conn len
    case mxc of
        Nothing -> return ()
        Just newMax -> do
            sendFrames conn RTT1Level [MaxData newMax]
            fire conn (Microseconds 50000) $
                sendFrames conn RTT1Level [MaxData newMax]
    return bs

-- | Closing a stream with an error code.
--   This sends RESET_STREAM to the peer.
--   This is an alternative of 'closeStream'.
resetStream :: Stream -> ApplicationProtocolError -> IO ()
resetStream s aerr = do
    let conn = streamConnection s
    let sid = streamId s
    sclosed <- isTxStreamClosed s
    unless sclosed $ do
        finalSize <- resetTxStream s
        lvl <- getEncryptionLevel conn
        let frame = ResetStream sid aerr finalSize
        putOutput conn $ OutControl lvl [frame]
    stopUnfinished s aerr
    -- Outside the guard above: whether or not the RESET_STREAM goes out, we
    -- are done with the stream, and 'recvStream' has to say so rather than
    -- block.  The peer's STOP_SENDING has closed the sending part already
    -- when an application resets a stream because 'sendStream' failed.
    setRxStreamClosed s
    releaseStream s

-- | Asking the peer to stop sending.
--   This sends STOP_SENDING to the peer
--   and it will send RESET_STREAM back.
--   'closeStream' should be called later.
stopStream :: Stream -> ApplicationProtocolError -> IO ()
stopStream s aerr = do
    let conn = streamConnection s
    let sid = streamId s
    sclosed <- isRxStreamClosed s
    unless sclosed $ do
        setRxStreamClosed s
        lvl <- getEncryptionLevel conn
        let frame = StopSending sid aerr
        putOutput conn $ OutControl lvl [frame]

-- | Sending a DATAGRAM frame to the peer.
--   If the datagram is larger than the peer's `max_datagram_frame_size`
--   an exception is thrown.
sendDatagram :: Connection -> ByteString -> IO ()
sendDatagram conn dat = do
    -- Determine the send level from connection readiness state rather than
    -- the encryptionLevel TVar, which is not set to RTT0Level during 0-RTT.
    ready1rtt <- isConnection1RTTReady conn
    lvl <-
        if ready1rtt
            then return RTT1Level
            else do
                ready0rtt <- isConnection0RTTReady conn
                if ready0rtt
                    then return RTT0Level
                    else E.throwIO $ ConnectionIsClosed "Cannot send DATAGRAM"
    limitBytes <- maxDatagramFrameSize <$> getPeerParameters conn
    when (limitBytes == 0) $
        E.throwIO $
            ConnectionIsClosed "DATAGRAM not supported by peer"
    let frameOverhead = 1 + BS.length (encodeInt (fromIntegral $ BS.length dat))
    when (BS.length dat + frameOverhead > limitBytes) $
        E.throwIO $
            ConnectionIsClosed "DATAGRAM size violation"
    let frame = Datagram False dat
    putOutput conn $ OutControl lvl [frame]

-- | Receiving a DATAGRAM frame.
--   This blocks until a DATAGRAM frame is received.
recvDatagram :: Connection -> IO ByteString
recvDatagram = atomically . recvDatagramSTM

-- | Receive all available DATAGRAM frames.
--   This function is non-blocking.
recvDatagramMany :: Connection -> IO [ByteString]
recvDatagramMany = atomically . flushTQueue . connRecvDatagramQ

-- | Receiving a DATAGRAM frame in STM.
recvDatagramSTM :: Connection -> STM ByteString
recvDatagramSTM conn = readTQueue (connRecvDatagramQ conn) `orElse` peerClosedSTM conn
