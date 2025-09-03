module Network.QUIC.IO where

import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as BS
import Network.Control

import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Imports
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
    -- fixme: size check for 0RTT
    let len = totalLen dats0
    ready <- isConnection1RTTReady conn
    if not ready
        then do
            -- 0-RTT
            putSendStreamQ conn $ TxStreamData s dats0 len False
            addTx conn s len
        else flowControl dats0 len False
  where
    conn = streamConnection s
    flowControl dats len wait = do
        -- 1-RTT
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
                -- fixme: RTT0Level?
                sendBlocked conn RTT1Level blocked
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
    let sid = streamId s
    closed <- isConnectionClosed conn
    sclosed <- isTxStreamClosed s
    unless (closed || sclosed) $ do
        setTxStreamClosed s
        setRxStreamClosed s
        putSendStreamQ conn $ TxStreamData s [] 0 True
        waitFinTx s
    delStream conn s
    when
        ( (isClient conn && isServerInitiatedBidirectional sid)
            || (isServer conn && isClientInitiatedBidirectional sid)
        )
        $ do
            -- FLOW CONTROL: MAX_STREAMS: recv: announcing my limit properly
            checkMaxStreams conn Bidirectional
    when
        ( (isClient conn && isServerInitiatedUnidirectional sid)
            || (isServer conn && isClientInitiatedUnidirectional sid)
        )
        $ do
            -- FLOW CONTROL: MAX_STREAMS: recv: announcing my limit properly
            checkMaxStreams conn Unidirectional
  where
    checkMaxStreams conn dir = do
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
    -> Int -- ^ Number of bytes to receive. In certain cases, `recvStream` can return
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
        setTxStreamClosed s
        setRxStreamClosed s
        lvl <- getEncryptionLevel conn
        let frame = ResetStream sid aerr 0
        putOutput conn $ OutControl lvl [frame]
    delStream conn s

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
