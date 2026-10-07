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

addTx :: Connection -> Stream -> Int -> IO ()
addTx conn s len = atomically $ do
    addTxStreamData s len
    addTxData conn len

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
        eblocked <- checkBlocked s len wait
        case eblocked of
            Right n
                | len == n -> do
                    putSendStreamQ conn $ TxStreamData s dats len False
                    addTx conn s n
                | otherwise -> do
                    let (dats1, dats2) = split n dats
                    putSendStreamQ conn $ TxStreamData s dats1 n False
                    addTx conn s n
                    flowControl dats2 (len - n) False
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

checkBlocked :: Stream -> Int -> Bool -> IO (Either Blocked Int)
checkBlocked s len wait = atomically $ do
    let conn = streamConnection s
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
    putSendStreamQ (streamConnection s) $ TxStreamData s [] 0 True
    waitFinTx s

-- | Closing a stream without an error.
--   This sends FIN if necessary.
closeStream :: Stream -> IO ()
closeStream s = do
    let conn = streamConnection s
        sid = streamId s
        -- A unidirectional stream of the peer's has no sending side here.
        -- Sending a FIN on it anyway made the peer close the connection with
        -- STREAM_STATE_ERROR, so that one could not be closed at all.
        receiveOnly =
            (isClient conn && isServerInitiatedUnidirectional sid)
                || (isServer conn && isClientInitiatedUnidirectional sid)
    closed <- isConnectionClosed conn
    sclosed <- isTxStreamClosed s
    unless (receiveOnly || closed || sclosed) $ do
        setTxStreamClosed s
        putSendStreamQ conn $ TxStreamData s [] 0 True
        waitFinTx s
    -- Outside the guard above: whether or not the FIN goes out, we are done
    -- with the stream, and 'recvStream' has to say so rather than block.
    setRxStreamClosed s
    delStream conn s
    releaseStream s

-- | Counting a stream of the peer's as done with, once, and announcing a
--   new MAX_STREAMS if that is due.
--
-- Only when the application is done with it: closing it or resetting it.  A
-- RESET_STREAM from the peer takes the stream out of the table, but whatever
-- is serving it may be at work yet, and counting it then would let a peer
-- that opens streams and resets them straight away have any number served
-- at once.
releaseStream :: Stream -> IO ()
releaseStream s = do
    first <- markReleased s
    when first $ do
        when
            ( (isClient conn && isServerInitiatedBidirectional sid)
                || (isServer conn && isClientInitiatedBidirectional sid)
            )
            $ do
                -- FLOW CONTROL: MAX_STREAMS: recv: announcing my limit properly
                checkMaxStreams Bidirectional
        when
            ( (isClient conn && isServerInitiatedUnidirectional sid)
                || (isServer conn && isClientInitiatedUnidirectional sid)
            )
            $ do
                -- FLOW CONTROL: MAX_STREAMS: recv: announcing my limit properly
                checkMaxStreams Unidirectional
        -- FLOW CONTROL: MAX_DATA: recv: the octets of this stream the
        -- application will never read.  Left uncounted, the window we
        -- advertise stays that much smaller for the rest of the connection:
        -- a server that answers a request without reading its body pays for
        -- that body until the connection ends, and enough of them leave the
        -- peer blocked by octets nobody is waiting for.
        unread <- takeRxUnread s
        -- And, if the peer has said where the stream ends, the rest of it:
        -- RFC 9000 Sec 4.5 has a receiver account for every octet sent on a
        -- stream, and what was lost on the way was still spent.
        uncounted <- takeRxUncounted s
        let owed = unread + uncounted
        when (owed > 0) $ do
            mx <- updateFlowRx conn owed
            forM_ mx $ \newMax -> do
                sendFrames conn RTT1Level [MaxData newMax]
                fire conn (Microseconds 50000) $
                    sendFrames conn RTT1Level [MaxData newMax]
        -- Where the peer has not said, what arrives from here on is still
        -- owed and the stream is gone, so what it owes is kept without it.
        keepDepartedStream conn s
  where
    conn = streamConnection s
    sid = streamId s
    checkMaxStreams dir = do
        mx <- checkStreamIdRoom conn dir
        case mx of
            Nothing -> return ()
            Just nms -> do
                sendFrames conn RTT1Level [MaxStreams dir nms]
                fire conn (Microseconds 50000) $
                    sendFrames conn RTT1Level [MaxStreams dir nms]

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
    forM_ mxs $ \newMax -> do
        sendFrames conn RTT1Level [MaxStreamData sid newMax]
        fire conn (Microseconds 50000) $
            sendFrames conn RTT1Level [MaxStreamData sid newMax]
    -- FLOW CONTROL: MAX_DATA: recv: announcing my limit properly
    mxc <- updateFlowRx conn len
    forM_ mxc $ \newMax -> do
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
        finalSize <- getTxStreamFinalSize s
        setTxStreamClosed s
        lvl <- getEncryptionLevel conn
        let frame = ResetStream sid aerr finalSize
        putOutput conn $ OutControl lvl [frame]
    -- Outside the guard above: whether or not the RESET_STREAM goes out, we
    -- are done with the stream, and 'recvStream' has to say so rather than
    -- block.  The peer's STOP_SENDING has closed the sending part already
    -- when an application resets a stream because 'sendStream' failed.
    setRxStreamClosed s
    delStream conn s
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
recvDatagramSTM = readTQueue . connRecvDatagramQ
