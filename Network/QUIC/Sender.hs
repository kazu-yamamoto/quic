{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Sender (
    sender,
    mkHeader,
    sendFinal,
) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as BS
import Foreign.Ptr (plusPtr)

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Qlog
import Network.QUIC.Recovery
import Network.QUIC.Stream
import Network.QUIC.Types

----------------------------------------------------------------

cryptoFrame :: Connection -> CryptoData -> EncryptionLevel -> IO Frame
cryptoFrame conn crypto lvl = do
    let len = BS.length crypto
    mstrm <- getCryptoStream conn lvl
    case mstrm of
        Nothing -> E.throwIO MustNotReached
        Just strm -> do
            off <- getTxStreamOffset strm len
            return $ CryptoF off crypto

----------------------------------------------------------------

sendPacket :: Connection -> [SentPacket] -> IO ()
sendPacket _ [] = return ()
sendPacket conn spkts0 = getMaxPacketSize conn >>= go
  where
    SizedBuffer buf0 bufsiz0 = encryptRes conn
    ldcc = connLDCC conn
    go maxSiz = do
        mx <-
            atomically
                ( (Just <$> takePingSTM ldcc)
                    `orElse` (Nothing <$ checkWindowOpenSTM ldcc maxSiz)
                )
        case mx of
            Just lvl | lvl `elem` [InitialLevel, HandshakeLevel] -> do
                sendPingPacket conn lvl
                go maxSiz
            _ -> do
                when (isJust mx) $ qlogDebug conn $ Debug "probe new"
                (sentPackets, leftsiz) <- buildPackets buf0 bufsiz0 maxSiz spkts0 id
                let bytes = bufsiz0 - leftsiz
                pathInfo <- getPathInfo conn
                when (isServer conn) $
                    waitAntiAmplificationFree conn pathInfo bytes
                -- If the secret of this level (e.g. HandshakeLevel)
                -- is already dropped, bytes is 0.
                when (bytes > 0) $ do
                    now <- getTimeMicrosecond
                    connSend conn buf0 bytes
                    addTxBytes conn bytes
                    addPathTxBytes pathInfo bytes
                    forM_ sentPackets $ \sentPacket0 -> do
                        let sentPacket = sentPacket0{spTimeSent = now}
                        qlogSent conn sentPacket now
                        onPacketSent ldcc sentPacket
    buildPackets _ _ _ [] _ = error "sendPacket: buildPackets"
    buildPackets buf bufsiz siz [spkt] build0 = do
        let pkt = spPlainPacket spkt
        (bytes, padlen) <-
            encodePlainPacket conn (SizedBuffer buf bufsiz) pkt $ Just siz
        if bytes < 0
            then return (build0 [], bufsiz)
            else do
                let sentPacket = fixSentPacket spkt bytes padlen
                return (build0 [sentPacket], bufsiz - bytes)
    buildPackets buf bufsiz siz (spkt : spkts) build0 = do
        let pkt = spPlainPacket spkt
        (bytes, padlen) <- encodePlainPacket conn (SizedBuffer buf bufsiz) pkt Nothing
        if bytes < 0
            then buildPackets buf bufsiz siz spkts build0
            else do
                let sentPacket = fixSentPacket spkt bytes padlen
                let build0' = build0 . (sentPacket :)
                    buf' = buf `plusPtr` bytes
                    bufsiz' = bufsiz - bytes
                    siz' = siz - spSentBytes sentPacket
                buildPackets buf' bufsiz' siz' spkts build0'

----------------------------------------------------------------

sendPingPacket :: Connection -> EncryptionLevel -> IO ()
sendPingPacket conn lvl = do
    pathInfo <- getPathInfo conn
    maxSiz <- getMaxPacketSize conn
    ok <-
        if isClient conn
            then return True
            else checkAntiAmplificationFree pathInfo maxSiz
    when ok $ do
        let ldcc = connLDCC conn
        mp <- releaseOldest ldcc lvl
        frames <- case mp of
            Nothing -> do
                qlogDebug conn $ Debug "probe ping"
                return [Ping]
            Just spkt -> do
                qlogDebug conn $ Debug "probe old"
                let PlainPacket _ plain0 = spPlainPacket spkt
                adjustForRetransmit conn $ plainFrames plain0
        xs <- construct conn lvl frames False
        if null xs
            then qlogDebug conn $ Debug "ping NULL"
            else do
                let spkt = last xs
                    ping = spPlainPacket spkt
                let sizbuf@(SizedBuffer buf _) = encryptRes conn
                (bytes, padlen) <- encodePlainPacket conn sizbuf ping (Just maxSiz)
                when (bytes > 0) $ do
                    now <- getTimeMicrosecond
                    connSend conn buf bytes
                    addTxBytes conn bytes
                    addPathTxBytes pathInfo bytes
                    let sentPacket0 = fixSentPacket spkt bytes padlen
                        sentPacket = sentPacket0{spTimeSent = now}
                    qlogSent conn sentPacket now
                    onPacketSent ldcc sentPacket

----------------------------------------------------------------

construct
    :: Connection
    -> EncryptionLevel
    -> [Frame]
    -> Bool
    -> IO [SentPacket]
construct conn lvl frames multilevel = do
    discarded <- getPacketNumberSpaceDiscarded ldcc lvl
    if discarded
        then return []
        else do
            established <- isConnectionEstablished conn
            if established || multilevel
                then do
                    constructTargetPacket
                else do
                    ppkt0 <- constructLowerAckPacket
                    ppkt1 <- constructTargetPacket
                    return (ppkt0 ++ ppkt1)
  where
    ldcc = connLDCC conn
    constructLowerAckPacket = do
        let lvl' = case lvl of
                HandshakeLevel -> InitialLevel
                RTT1Level -> HandshakeLevel
                _ -> RTT1Level
        if lvl' == RTT1Level
            then return []
            else do
                ppns <- getPeerPacketNumbers ldcc lvl'
                if nullPeerPacketNumbers ppns
                    then return []
                    else mkPlainPacket conn lvl' [] ppns
    constructTargetPacket
        | null frames = do
            -- ACK only packet
            resetDealyedAck conn
            ppns <- getPeerPacketNumbers ldcc lvl
            if nullPeerPacketNumbers ppns
                then return []
                else
                    if lvl == RTT1Level
                        then do
                            prevppns <- getPreviousRTT1PPNs ldcc
                            if ppns /= prevppns
                                then do
                                    setPreviousRTT1PPNs ldcc ppns
                                    mkPlainPacket conn lvl [] ppns
                                else return []
                        else mkPlainPacket conn lvl [] ppns
        | otherwise = do
            resetDealyedAck conn
            ppns <- getPeerPacketNumbers ldcc lvl
            mkPlainPacket conn lvl frames ppns

mkPlainPacket
    :: Connection -> EncryptionLevel -> [Frame] -> PeerPacketNumbers -> IO [SentPacket]
mkPlainPacket conn lvl frames0 ppns = do
    let ackEli
            | null frames0 = False
            | otherwise = True
        frames
            | nullPeerPacketNumbers ppns = frames0
            | otherwise = mkAck ppns : frames0
    header <- mkHeader conn lvl
    mypn <- nextPacketNumber conn
    let convert = onPlainCreated $ connHooks conn
        plain = convert lvl $ Plain (Flags 0) mypn frames 0
        ppkt = PlainPacket header plain
    return [mkSentPacket mypn lvl ppkt ppns ackEli]
  where
    mkAck ps = Ack (toAckInfo $ fromPeerPacketNumbers ps) 0

mkHeader :: Connection -> EncryptionLevel -> IO Header
mkHeader conn lvl = do
    ver <- getVersion conn
    mycid <- getMyCID conn
    peercid <- getPeerCID conn
    token <- if lvl == InitialLevel then getToken conn else return ""
    return $ case lvl of
        InitialLevel -> Initial ver peercid mycid token
        RTT0Level -> RTT0 ver peercid mycid
        HandshakeLevel -> Handshake ver peercid mycid
        RTT1Level -> Short peercid

----------------------------------------------------------------

data Switch
    = SwPing EncryptionLevel
    | SwOut Output
    | SwStrm TxStreamData

sender :: Connection -> IO ()
sender conn = handleLogT logAction loop
  where
    loop = do
        exit <- atomically $ do
            done <- readTVar $ connDone conn
            a <- isEmptyPingSTM (connLDCC conn)
            b <- isEmptyOutputSTM conn
            c <- isEmptyStreamSTM conn
            if done
                then return (a && b && c)
                else if (not a || not b || not c) then return False else retry
        if exit
            then
                E.throwIO ExitConnection
            else do
                sendP conn
                loop
    logAction msg = connDebugLog conn ("debug: sender: " <> msg)

sendP :: Connection -> IO ()
sendP conn = do
    x <-
        atomically
            ( (SwPing <$> takePingSTM (connLDCC conn))
                `orElse` (SwOut <$> takeOutputSTM conn)
                `orElse` (SwStrm <$> takeSendStreamQSTM conn)
            )
    case x of
        SwPing lvl -> sendPingPacket conn lvl
        SwOut out -> sendOutput conn out
        SwStrm tx -> sendTxStreamData conn tx

sendFinal :: Connection -> IO ()
sendFinal conn = loop 30
  where
    msg = "sendFinal " ++ if isServer conn then "Server" else "Client"
    loop :: Int -> IO ()
    loop 0 = return ()
    loop n = do
        mx <- timeout (Microseconds 10) msg $ sendP conn
        case mx of
            Nothing -> return ()
            Just () -> loop (n - 1)

----------------------------------------------------------------

discardClientInitialPacketNumberSpace :: Connection -> IO ()
discardClientInitialPacketNumberSpace conn
    | isClient conn = do
        let ldcc = connLDCC conn
        discarded <- getAndSetPacketNumberSpaceDiscarded ldcc InitialLevel
        unless discarded $ fire conn (Microseconds 100000) $ do
            dropSecrets conn InitialLevel
            clearCryptoStream conn InitialLevel
            onPacketNumberSpaceDiscarded ldcc InitialLevel
    | otherwise = return ()

sendOutput :: Connection -> Output -> IO ()
sendOutput conn (OutControl RTT1Level []) = do
    exist <- atomically $ do
        b1 <- not <$> isEmptyCryptoSTM conn
        b2 <- not <$> isEmptyOutputSTM conn
        b3 <- not <$> isEmptyStreamSTM conn
        return (b1 || b2 || b3)
    unless exist $ construct conn RTT1Level [] False >>= sendPacket conn
sendOutput conn (OutControl lvl frames) = do
    mout <- tryPeekOutput conn
    case mout of
        Just (OutControl lvl' frames')
            | lvl == lvl' -> do
                construct conn lvl (frames ++ frames') False >>= sendPacket conn
                void $ atomically $ takeOutputSTM conn
        _ -> construct conn lvl frames False >>= sendPacket conn
    when (lvl == HandshakeLevel) $ discardClientInitialPacketNumberSpace conn
sendOutput conn (OutHandshake lcs0) = do
    let convert = onTLSHandshakeCreated $ connHooks conn
        (lcs, wait) = convert lcs0
    -- only for h3spec
    when wait $ wait0RTTReady conn
    sendCryptoFragments conn lcs
    when (any (\(l, _) -> l == HandshakeLevel) lcs) $
        discardClientInitialPacketNumberSpace conn
sendOutput conn (OutRetrans (PlainPacket hdr0 plain0)) = do
    frames <- adjustForRetransmit conn $ plainFrames plain0
    let lvl = levelFromHeader hdr0
    construct conn lvl frames False >>= sendPacket conn

levelFromHeader :: Header -> EncryptionLevel
levelFromHeader hdr
    | lvl == RTT0Level = RTT1Level
    | otherwise = lvl
  where
    lvl = packetEncryptionLevel hdr

adjustForRetransmit :: Connection -> [Frame] -> IO [Frame]
adjustForRetransmit _ [] = return []
adjustForRetransmit conn (Padding{} : xs) = adjustForRetransmit conn xs
adjustForRetransmit conn (Ack{} : xs) = adjustForRetransmit conn xs
adjustForRetransmit conn (MaxStreamData sid _ : xs) = do
    mstrm <- findStream conn sid
    case mstrm of
        Nothing -> adjustForRetransmit conn xs
        Just strm -> do
            newMax <- getRxMaxStreamData strm
            let r = MaxStreamData sid newMax
            rs <- adjustForRetransmit conn xs
            return (r : rs)
adjustForRetransmit conn (MaxData{} : xs) = do
    newMax <- getRxMaxData conn
    let r = MaxData newMax
    rs <- adjustForRetransmit conn xs
    return (r : rs)
adjustForRetransmit conn (x : xs) = do
    rs <- adjustForRetransmit conn xs
    return (x : rs)

limitationC :: Int
limitationC = 1024

thresholdC :: Int
thresholdC = 200

sendCryptoFragments :: Connection -> [(EncryptionLevel, CryptoData)] -> IO ()
sendCryptoFragments _ [] = return ()
sendCryptoFragments conn lcs = do
    loop limitationC id lcs
  where
    multilevel = length lcs >= 2
    loop
        :: Int
        -> ([SentPacket] -> [SentPacket])
        -> [(EncryptionLevel, CryptoData)]
        -> IO ()
    loop _ build0 [] = do
        let spkts0 = build0 []
        unless (null spkts0) $ sendPacket conn spkts0
    loop len0 build0 ((lvl, bs) : xs) | BS.length bs > len0 = do
        let (target, rest) = BS.splitAt len0 bs
        frame1 <- cryptoFrame conn target lvl
        spkts1 <- construct conn lvl [frame1] multilevel
        sendPacket conn $ build0 spkts1
        -- to calculate multilevel again, let's call sendCryptoFragments
        sendCryptoFragments conn ((lvl, rest) : xs)
    loop _ build0 [(lvl, bs)] = do
        frame1 <- cryptoFrame conn bs lvl
        spkts1 <- construct conn lvl [frame1] multilevel
        sendPacket conn $ build0 spkts1
    loop len0 build0 ((lvl, bs) : xs) | len0 - BS.length bs < thresholdC = do
        frame1 <- cryptoFrame conn bs lvl
        spkts1 <- construct conn lvl [frame1] multilevel
        sendPacket conn $ build0 spkts1
        loop limitationC id xs
    loop len0 build0 ((lvl, bs) : xs) = do
        frame1 <- cryptoFrame conn bs lvl
        spkts1 <- construct conn lvl [frame1] multilevel
        let len1 = len0 - BS.length bs
            build1 = build0 . (spkts1 ++)
        loop len1 build1 xs

----------------------------------------------------------------

threshold :: Int
threshold = 832

limitation :: Int
limitation = 1040

packFin :: Connection -> Stream -> Bool -> IO Bool
packFin _ _ True = return True
packFin conn s False = do
    mx <- tryPeekSendStreamQ conn
    case mx of
        Just (TxStreamData s1 [] 0 True)
            | streamId s == streamId s1 -> do
                _ <- takeSendStreamQ conn
                return True
        _ -> return False

sendTxStreamData :: Connection -> TxStreamData -> IO ()
sendTxStreamData conn (TxStreamData s dats len fin0) = do
    fin <- packFin conn s fin0
    if len < limitation
        then sendStreamSmall conn s dats fin len
        else sendStreamLarge conn s dats fin

sendStreamSmall :: Connection -> Stream -> [StreamData] -> Bool -> Int -> IO ()
sendStreamSmall conn s0 dats0 fin0 len0 = do
    off0 <- getTxStreamOffset s0 len0
    let sid0 = streamId s0
        frame0 = StreamF sid0 off0 dats0 fin0
        sb = if fin0 then (s0 :) else id
    (frames, streams) <- loop s0 frame0 len0 id sb
    ready <- isConnection1RTTReady conn
    let lvl
            | ready = RTT1Level
            | otherwise = RTT0Level
    construct conn lvl frames False >>= sendPacket conn
    mapM_ syncFinTx streams
  where
    tryPeek = do
        mx <- tryPeekSendStreamQ conn
        case mx of
            Nothing -> do
                yield
                tryPeekSendStreamQ conn
            Just _ -> return mx
    loop
        :: Stream
        -> Frame
        -> Int
        -> ([Frame] -> [Frame])
        -> ([Stream] -> [Stream])
        -> IO ([Frame], [Stream])
    loop s frame total build sb = do
        mx <- tryPeek
        case mx of
            Nothing -> return (build [frame], sb [])
            Just (TxStreamData s1 dats1 len1 fin1) -> do
                let total1 = len1 + total
                if total1 < limitation
                    then do
                        _ <- takeSendStreamQ conn -- cf tryPeek
                        fin1' <- packFin conn s1 fin1 -- must be after takeSendStreamQ
                        off1 <- getTxStreamOffset s1 len1
                        let sid = streamId s
                            sid1 = streamId s1
                        if sid == sid1
                            then do
                                let (off, dats) = case frame of
                                        StreamF _ o d _ -> (o, d)
                                        _ -> error "sendStreamSmall"
                                    frame1 = StreamF sid off (dats ++ dats1) fin1'
                                    sb1 = if fin1' then sb . (s1 :) else sb
                                loop s1 frame1 total1 build sb1
                            else do
                                let frame1 = StreamF sid1 off1 dats1 fin1'
                                    build1 = build . (frame :)
                                    sb1 = if fin1' then sb . (s1 :) else sb
                                loop s1 frame1 total1 build1 sb1
                    else return (build [frame], sb [])

sendStreamLarge :: Connection -> Stream -> [ByteString] -> Bool -> IO ()
sendStreamLarge conn s dats0 fin0 = do
    loop dats0
    when fin0 $ syncFinTx s
  where
    sid = streamId s
    loop [] = return ()
    loop dats = do
        let (dats1, dats2) = splitChunks dats
            len = totalLen dats1
        off <- getTxStreamOffset s len
        let fin = fin0 && null dats2
            frame = StreamF sid off dats1 fin
        ready <- isConnection1RTTReady conn
        let lvl
                | ready = RTT1Level
                | otherwise = RTT0Level
        construct conn lvl [frame] False >>= sendPacket conn
        loop dats2

-- Typical case: [3, 1024, 1024, 1024, 200]
splitChunks :: [ByteString] -> ([ByteString], [ByteString])
splitChunks bs0 = loop bs0 0 id
  where
    loop [] _ build = let curr = build [] in (curr, [])
    loop bbs@(b : bs) siz0 build
        | siz <= threshold = let build' = build . (b :) in loop bs siz build'
        | siz <= limitation = let curr = build [b] in (curr, bs)
        | len > limitation =
            let (u, b') = BS.splitAt (limitation - siz0) b
                curr = build [u]
                bs' = b' : bs
             in (curr, bs')
        | otherwise = let curr = build [] in (curr, bbs)
      where
        len = BS.length b
        siz = siz0 + len
