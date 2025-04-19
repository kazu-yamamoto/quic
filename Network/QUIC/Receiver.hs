{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver (
    receiver,
) where

import qualified Control.Exception as E
import qualified Data.ByteString as BS
import Network.Control
import Network.TLS (AlertDescription (..))
import System.Log.FastLogger

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Crypto
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Info
import Network.QUIC.Logger
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Recovery
import Network.QUIC.Stream
import Network.QUIC.Types as QUIC

receiver :: Connection -> IO ()
receiver conn = handleLogT logAction body
  where
    body = do
        loopHandshake
        loopEstablished
    recvTimeout = do
        -- The spec says that CC is not sent when timeout.
        -- But we intentionally sends CC when timeout.
        ito <- readMinIdleTimeout conn
        mx <- timeout ito "recvTimeout" $ connRecv conn -- fixme: taking minimum with peer's one
        case mx of
            Nothing -> do
                st <- getConnectionState conn
                let msg0
                        | isClient conn = "Client"
                        | otherwise = "Server"
                    msg = msg0 ++ " " ++ show st
                qlogDebug conn $ Debug "recv timeout"
                E.throwIO $ ConnectionIsTimeout msg
            Just x -> return x
    loopHandshake = do
        rpkt <- recvTimeout
        processReceivedPacketHandshake conn rpkt
        established <- isConnectionEstablished conn
        unless established loopHandshake
    loopEstablished = forever $ do
        rpkt <- recvTimeout
        let CryptPacket hdr _ = rpCryptPacket rpkt
            cid = headerMyCID hdr
        included <- myCIDsInclude conn cid
        case included of
            Just nseq -> do
                -- RFC 9000 Sec 5.1.1: If an endpoint provided fewer
                -- connection IDs than the peer's
                -- active_connection_id_limit, it MAY supply a new
                -- connection ID when it receives a packet with a
                -- previously unused connection ID.
                shouldUpdate <- shouldUpdateMyCID conn nseq
                capOK <- checkPeerCIDCapacity conn
                when (shouldUpdate && capOK) $ do
                    setMyCID conn cid
                    cidInfo <- getNewMyCID conn
                    when (isServer conn) $ do
                        register <- getRegister conn
                        register (cidInfoCID cidInfo) conn
                    sent <- readIORef (sentRetirePriorTo conn)
                    writeIORef (sentRetirePriorTo conn) False
                    unless sent $
                        sendFrames conn RTT1Level [NewConnectionID cidInfo 0]
                processReceivedPacket conn rpkt
                shouldUpdatePeer <-
                    if shouldUpdate
                        then shouldUpdatePeerCID conn
                        else return False
                when shouldUpdatePeer $ choosePeerCIDForPrivacy conn
            _ -> do
                qlogDropped conn (hdr, "unknown_connection_id" :: String)
                connDebugLog conn $ bhow cid <> " is unknown"
    logAction msg = connDebugLog conn ("debug: receiver: " <> msg)

processReceivedPacketHandshake :: Connection -> ReceivedPacket -> IO ()
processReceivedPacketHandshake conn rpkt = do
    let CryptPacket hdr _ = rpCryptPacket rpkt
        lvl = rpEncryptionLevel rpkt
        msg =
            "processReceivedPacketHandshake "
                ++ if isServer conn then "Server" else "Client"
    mx <- timeout (Microseconds 10000) msg $ waitEncryptionLevel conn lvl
    case mx of
        Nothing -> do
            putOffCrypto conn lvl rpkt
            when (isClient conn) $ do
                lvl' <- getEncryptionLevel conn
                speedup (connLDCC conn) lvl' ("not decryptable: " <> toLogStr (show lvl))
        Just ()
            | isClient conn -> do
                when (lvl == InitialLevel) $ do
                    peercid <- getPeerCID conn
                    let newPeerCID = headerPeerCID hdr
                    when (peercid /= headerPeerCID hdr) $
                        resetPeerCID conn newPeerCID
                    setPeerAuthCIDs conn $ \auth ->
                        auth{initSrcCID = Just newPeerCID}
                case hdr of
                    Initial peerVer _ _ _ -> do
                        myVer <- getVersion conn
                        let myOrigiVer = getOriginalVersion conn
                            firstTime = myVer == myOrigiVer
                        when (firstTime && myVer /= peerVer) $ do
                            setVersion conn peerVer
                            dcid <- getClientDstCID conn
                            initializeCoder conn InitialLevel $ initialSecrets peerVer dcid
                            qlogDebug conn $ Debug "Version changed"
                    _ -> return ()
                processReceivedPacket conn rpkt
            | otherwise -> do
                mycid <- getMyCID conn
                when
                    ( lvl == HandshakeLevel
                        || (lvl == InitialLevel && mycid == headerMyCID hdr)
                    )
                    $ do
                        getPathInfo conn >>= setAddressValidated
                when (lvl == HandshakeLevel) $ do
                    let ldcc = connLDCC conn
                    discarded <- getAndSetPacketNumberSpaceDiscarded ldcc InitialLevel
                    unless discarded $ fire conn (Microseconds 100000) $ do
                        dropSecrets conn InitialLevel
                        clearCryptoStream conn InitialLevel
                        onPacketNumberSpaceDiscarded ldcc InitialLevel
                processReceivedPacket conn rpkt

rateLimit :: Int
rateLimit = 10

checkRate :: [Frame] -> Int
checkRate fs0 = go fs0 0
  where
    go [] n = n
    go (f : fs) n
        | rateControled f = go fs (n + 1)
        | otherwise = go fs n

processReceivedPacket :: Connection -> ReceivedPacket -> IO ()
processReceivedPacket conn rpkt = do
    let CryptPacket hdr crypt = rpCryptPacket rpkt
        lvl = rpEncryptionLevel rpkt
        tim = rpTimeRecevied rpkt
    mplain <- decryptCrypt conn crypt lvl
    case mplain of
        Just plain@Plain{..} -> do
            addRxBytes conn $ rpReceivedBytes rpkt
            pathInfo <- getPathInfo conn
            addPathRxBytes pathInfo $ rpReceivedBytes rpkt
            when (isIllegalReservedBits plainMarks || isNoFrames plainMarks) $
                closeConnection conn ProtocolViolation "Non 0 RR bits or no frames"
            when (isUnknownFrame plainMarks) $
                closeConnection conn FrameEncodingError "Unknown frame"
            let controlled = checkRate plainFrames
            when (controlled /= 0) $ do
                rate <- addRate (controlRate conn) controlled
                when (rate > rateLimit) $ do
                    closeConnection conn QUIC.InternalError "Rate control"
            -- For Ping, record PPN first, then send an ACK.
            onPacketReceived (connLDCC conn) lvl plainPacketNumber
            when (lvl == RTT1Level) $ setPeerPacketNumber conn plainPacketNumber
            qlogReceived conn (PlainPacket hdr plain) tim
            let ackEli = any ackEliciting plainFrames
            (ckp, cpn) <- getCurrentKeyPhase conn
            let Flags flags = plainFlags
                nkp = flags `testBit` 2
            when (nkp /= ckp && plainPacketNumber > cpn) $ do
                setCurrentKeyPhase conn nkp plainPacketNumber
                updateCoder1RTT conn ckp -- ckp is now next
            mapM_ (processFrame conn lvl) plainFrames
            when ackEli $ do
                case lvl of
                    RTT0Level -> return ()
                    RTT1Level -> delayedAck conn
                    _ -> do
                        sup <- getSpeedingUp (connLDCC conn)
                        when sup $ do
                            qlogDebug conn $ Debug "ping for speedup"
                            sendFrames conn lvl [Ping]
        Nothing -> do
            qlogDropped conn (hdr, "decrypt_error" :: String)
            connDebugLog conn $
                "debug: cannot decrypt: "
                    <> bhow lvl
                    <> " size = "
                    <> bhow (BS.length $ cryptPacket crypt)

isSendOnly :: Connection -> StreamId -> Bool
isSendOnly conn sid
    | isClient conn = isClientInitiatedUnidirectional sid
    | otherwise = isServerInitiatedUnidirectional sid

isReceiveOnly :: Connection -> StreamId -> Bool
isReceiveOnly conn sid
    | isClient conn = isServerInitiatedUnidirectional sid
    | otherwise = isClientInitiatedUnidirectional sid

isInitiated :: Connection -> StreamId -> Bool
isInitiated conn sid
    | isClient conn = isClientInitiated sid
    | otherwise = isServerInitiated sid

guardStream :: Connection -> StreamId -> Maybe Stream -> IO ()
guardStream conn sid Nothing =
    streamNotCreatedYet
        conn
        sid
        "a locally-initiated stream that has not yet been created"
guardStream _ _ _ = return ()

-- fixme: what about unidirection stream?
streamNotCreatedYet :: Connection -> StreamId -> ReasonPhrase -> IO ()
streamNotCreatedYet conn sid emsg
    | isInitiated conn sid = do
        curSid <- getMyStreamId conn
        when (sid > curSid) $
            closeConnection conn StreamStateError emsg
streamNotCreatedYet _ _ _ = return ()

processFrame :: Connection -> EncryptionLevel -> Frame -> IO ()
processFrame _ _ Padding{} = return ()
processFrame conn lvl Ping = do
    -- see ackEli above
    when (lvl /= InitialLevel && lvl /= RTT1Level) $ sendFrames conn lvl []
processFrame conn lvl (Ack ackInfo ackDelay) = do
    when (lvl == RTT0Level) $ closeConnection conn ProtocolViolation "ACK"
    onAckReceived (connLDCC conn) lvl ackInfo $ milliToMicro ackDelay
processFrame conn lvl (ResetStream sid aerr _finlen) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection conn ProtocolViolation "RESET_STREAM"
    when (isSendOnly conn sid) $
        closeConnection conn StreamStateError "Received in a send-only stream"
    mstrm <- findStream conn sid
    case mstrm of
        Nothing -> return ()
        Just strm -> do
            onResetStreamReceived (connHooks conn) strm aerr
            setTxStreamClosed strm
            setRxStreamClosed strm
            delStream conn strm
processFrame conn lvl (StopSending sid err) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection conn ProtocolViolation "STOP_SENDING"
    when (isReceiveOnly conn sid) $
        closeConnection conn StreamStateError "Receive-only stream"
    mstrm <- findStream conn sid
    case mstrm of
        Nothing -> streamNotCreatedYet conn sid "No such stream for STOP_SENDING"
        Just _strm -> sendFramesLim conn lvl [ResetStream sid err 0]
processFrame _ _ (CryptoF _ "") = return ()
processFrame conn lvl (CryptoF off cdat) = do
    when (lvl == RTT0Level) $
        closeConnection conn ProtocolViolation "CRYPTO in 0-RTT"
    let len = BS.length cdat
        rx = RxStreamData cdat off len False
    case lvl of
        InitialLevel -> do
            dup <- putRxCrypto conn lvl rx
            when dup $ speedup (connLDCC conn) lvl "duplicated"
        RTT0Level -> do
            connDebugLog conn $ "processFrame: invalid packet type " <> bhow lvl
        HandshakeLevel -> do
            dup <- putRxCrypto conn lvl rx
            when dup $ speedup (connLDCC conn) lvl "duplicated"
        RTT1Level
            | isClient conn ->
                void $ putRxCrypto conn lvl rx
            | otherwise ->
                closeConnection conn (cryptoError UnexpectedMessage) "CRYPTO in 1-RTT"
processFrame conn lvl (NewToken token) = do
    when (isServer conn || lvl /= RTT1Level) $
        closeConnection conn ProtocolViolation "NEW_TOKEN for server or in 1-RTT"
    when (isClient conn) $ setNewToken conn token
processFrame conn RTT0Level (StreamF sid off (dat : _) fin) = do
    when (off == 0) $ updatePeerStreamId conn sid
    -- FLOW CONTROL: MAX_STREAMS: recv: rejecting if over my limit
    ok <- checkRxMaxStreams conn sid
    unless ok $ closeConnection conn StreamLimitError "stream id is too large"
    when (isSendOnly conn sid) $
        closeConnection conn StreamStateError "send-only stream"
    mstrm <- findStream conn sid
    guardStream conn sid mstrm
    strm <- maybe (createStream conn sid) return mstrm
    let len = BS.length dat
        rx = RxStreamData dat off len fin
    fc <- putRxStreamData strm rx
    case fc of
        -- FLOW CONTROL: MAX_STREAM_DATA: recv: rejecting if over my limit
        OverLimit ->
            closeConnection conn FlowControlError "Flow control error for stream in 0-RTT"
        Duplicated -> return ()
        Reassembled -> do
            ok' <- checkRxMaxData conn len
            -- FLOW CONTROL: MAX_DATA: send: respecting peer's limit
            unless ok' $
                closeConnection
                    conn
                    FlowControlError
                    "Flow control error for connection in 0-RTT"
processFrame conn RTT1Level (StreamF sid _ [""] False) = do
    -- FLOW CONTROL: MAX_STREAMS: recv: rejecting if over my limit
    ok <- checkRxMaxStreams conn sid
    unless ok $ closeConnection conn StreamLimitError "stream id is too large"
    when (isSendOnly conn sid) $
        closeConnection conn StreamStateError "send-only stream"
    mstrm <- findStream conn sid
    guardStream conn sid mstrm
processFrame conn RTT1Level (StreamF sid off (dat : _) fin) = do
    when (off == 0) $ updatePeerStreamId conn sid
    -- FLOW CONTROL: MAX_STREAMS: recv: rejecting if over my limit
    ok <- checkRxMaxStreams conn sid
    unless ok $ closeConnection conn StreamLimitError "stream id is too large"
    when (isSendOnly conn sid) $
        closeConnection conn StreamStateError "send-only stream"
    mstrm <- findStream conn sid
    guardStream conn sid mstrm
    strm <- maybe (createStream conn sid) return mstrm
    let len = BS.length dat
        rx = RxStreamData dat off len fin
    fc <- putRxStreamData strm rx
    case fc of
        -- FLOW CONTROL: MAX_STREAM_DATA: recv: rejecting if over my limit
        OverLimit ->
            closeConnection conn FlowControlError "Flow control error for stream in 1-RTT"
        Duplicated -> return ()
        Reassembled -> do
            ok' <- checkRxMaxData conn len
            -- FLOW CONTROL: MAX_DATA: send: respecting peer's limit
            unless ok' $
                closeConnection
                    conn
                    FlowControlError
                    "Flow control error for connection in 1-RTT"
processFrame conn lvl (MaxData n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection conn ProtocolViolation "MAX_DATA in Initial or Handshake"
    setTxMaxData conn n
processFrame conn lvl (MaxStreamData sid n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection conn ProtocolViolation "MAX_STREAM_DATA in Initial or Handshake"
    when (isReceiveOnly conn sid) $
        closeConnection conn StreamStateError "Receive-only stream"
    mstrm <- findStream conn sid
    case mstrm of
        Nothing -> streamNotCreatedYet conn sid "No such stream for MAX_STREAM_DATA"
        Just strm -> setTxMaxStreamData strm n
processFrame conn lvl (MaxStreams dir n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection conn ProtocolViolation "MAX_STREAMS in Initial or Handshake"
    when (n > 2 ^ (60 :: Int)) $
        closeConnection conn FrameEncodingError "Too large MAX_STREAMS"
    if dir == Bidirectional
        then setTxMaxStreams conn n
        else setTxUniMaxStreams conn n
processFrame _conn _lvl DataBlocked{} = return ()
processFrame _conn _lvl (StreamDataBlocked _sid _) = return ()
processFrame conn lvl (StreamsBlocked _dir n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection conn ProtocolViolation "STREAMS_BLOCKED in Initial or Handshake"
    when (n > 2 ^ (60 :: Int)) $
        closeConnection conn FrameEncodingError "Too large STREAMS_BLOCKED"
processFrame conn lvl (NewConnectionID cidInfo retirePriorTo) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection
            conn
            ProtocolViolation
            "NEW_CONNECTION_ID in Initial or Handshake"
    let (_, cidlen) = unpackCID $ cidInfoCID cidInfo
        seqNum = cidInfoSeq cidInfo
    when (cidlen < 1 || 20 < cidlen || retirePriorTo > seqNum) $
        closeConnection conn FrameEncodingError "NEW_CONNECTION_ID parameter error"
    -- Retiring CIDs first then add a new CID.
    --
    -- RFC 9000 Sec 5.1.1 says:
    -- An endpoint MAY send connection IDs that temporarily exceed a
    -- peer's limit if the NEW_CONNECTION_ID frame also requires the
    -- retirement of any excess, by including a sufficiently large
    -- value in the Retire Prior To field.
    prevRetirePriorTo <- getPeerRetirePriorTo conn
    -- RFC 900 Sec 19.15 says:
    -- Once a sender indicates a Retire Prior To value, smaller values
    -- sent in subsequent NEW_CONNECTION_ID frames have no effect. A
    -- receiver MUST ignore any Retire Prior To fields that do not
    -- increase the largest received Retire Prior To value.
    when (retirePriorTo >= prevRetirePriorTo) $ do
        -- RFC 9000 Sec 5.1.2 says:
        -- Upon receipt of an increased Retire Prior To field, the
        -- peer MUST stop using the corresponding connection IDs and
        -- retire them with RETIRE_CONNECTION_ID frames before adding
        -- the newly provided connection ID to the set of active
        -- connection IDs.
        seqNums <- setPeerCIDAndRetireCIDs conn retirePriorTo -- upadting RPT
        sendFramesLim conn RTT1Level $ map RetireConnectionID seqNums
    -- Adding a new CID
    if seqNum < prevRetirePriorTo
        then
            -- RFC 9000 Sec 19.15 says:
            -- An endpoint that receives a NEW_CONNECTION_ID frame
            -- with a sequence number smaller than the Retire Prior To
            -- field of a previously received NEW_CONNECTION_ID frame
            -- MUST send a corresponding RETIRE_CONNECTION_ID frame
            -- that retires the newly received connection ID, unless
            -- it has already done so for that sequence number.
            sendFramesLim conn RTT1Level [RetireConnectionID seqNum]
        else do
            ok <- addPeerCID conn cidInfo
            unless ok $
                closeConnection conn ConnectionIdLimitError "NEW_CONNECTION_ID limit error"
processFrame conn RTT1Level (RetireConnectionID sn) = do
    -- FIXME: CID is necessary here
    -- The sequence number specified in a RETIRE_CONNECTION_ID frame
    -- MUST NOT refer to the Destination Connection ID field of the
    -- packet in which the frame is contained. The peer MAY treat this
    -- as a connection error of type PROTOCOL_VIOLATION.
    mcidInfo <- retireMyCID conn sn
    case mcidInfo of
        Nothing -> return ()
        Just cidInfo -> do
            -- Don't send NewConnectionID since we don't know it is
            -- ping or pong. If this is a pong, NewConnectionID should
            -- not be send back. Instead, loopEstablished sends it
            -- when CID is changed.
            when (isServer conn) $ do
                unregister <- getUnregister conn
                unregister $ cidInfoCID cidInfo
processFrame conn RTT1Level (PathChallenge dat) =
    sendFramesLim conn RTT1Level [PathResponse dat]
processFrame conn RTT1Level (PathResponse dat) =
    -- RTT0Level falls intentionally
    checkResponse conn dat
processFrame conn _lvl (ConnectionClose NoError _ftyp _reason) =
    when (isServer conn) $ E.throwIO ConnectionIsClosed
processFrame _conn _lvl (ConnectionClose err _ftyp reason) = do
    let quicexc = TransportErrorIsReceived err reason
    E.throwIO quicexc
processFrame _conn _lvl (ConnectionCloseApp err reason) = do
    let quicexc = ApplicationProtocolErrorIsReceived err reason
    E.throwIO quicexc
processFrame conn lvl HandshakeDone = do
    when (isServer conn || lvl /= RTT1Level) $
        closeConnection conn ProtocolViolation "HANDSHAKE_DONE for server"
    fire conn (Microseconds 100000) $ do
        let ldcc = connLDCC conn
        discarded0 <- getAndSetPacketNumberSpaceDiscarded ldcc RTT0Level
        unless discarded0 $ dropSecrets conn RTT0Level
        discarded1 <- getAndSetPacketNumberSpaceDiscarded ldcc HandshakeLevel
        unless discarded1 $ do
            dropSecrets conn HandshakeLevel
            onPacketNumberSpaceDiscarded ldcc HandshakeLevel
        clearCryptoStream conn HandshakeLevel
        clearCryptoStream conn RTT1Level
    setConnectionEstablished conn
    getConnectionInfo conn >>= onConnectionEstablished (connHooks conn)
    -- to receive NewSessionTicket
    fire conn (Microseconds 1000000) $ killHandshaker conn lvl
processFrame conn _ _ = closeConnection conn ProtocolViolation "Frame is not allowed"

-- Return value indicates duplication.
putRxCrypto :: Connection -> EncryptionLevel -> RxStreamData -> IO Bool
putRxCrypto conn lvl rx = do
    mstrm <- getCryptoStream conn lvl
    case mstrm of
        Nothing -> return False
        Just strm -> do
            let put = putCrypto conn . InpHandshake lvl
                putFin = return ()
            tryReassemble strm rx put putFin

killHandshaker :: Connection -> EncryptionLevel -> IO ()
killHandshaker conn lvl = putCrypto conn $ InpHandshake lvl ""
