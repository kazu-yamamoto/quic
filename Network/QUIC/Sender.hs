{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Sender (
    sender
  ) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Data.ByteString as B

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
    let len = B.length crypto
    strm <- getCryptoStream conn lvl
    off <- getTxStreamOffset strm len
    return $ CryptoF off crypto

----------------------------------------------------------------

sendPacket :: Connection -> SendMany -> [SentPacket] -> IO ()
sendPacket _ _ [] = return ()
sendPacket conn send spkts = getMaxPacketSize conn >>= go
  where
    ldcc = connLDCC conn
    go maxSiz = do
        mx <- atomically ((Just    <$> takePingSTM ldcc)
                 `orElse` (Nothing <$  checkWindowOpenSTM ldcc maxSiz))
        case mx of
          Just lvl | lvl `elem` [InitialLevel,HandshakeLevel] -> do
            sendPingPacket conn send lvl
            go maxSiz
          _ -> do
            when (isJust mx) $ qlogDebug conn $ Debug "probe new"
            (sentPackets, bss) <- buildPackets maxSiz spkts id id
            let tlen = totalLen bss
            when (isServer conn) $ waitAntiAmplificationFree conn tlen
            now <- getTimeMicrosecond
            send bss
            addTxBytes conn tlen
            forM_ sentPackets $ \sentPacket0 -> do
                let sentPacket = sentPacket0 { spTimeSent = now }
                qlogSent conn sentPacket now
                onPacketSent ldcc sentPacket
    buildPackets _ [] _ _ = error "sendPacket: buildPackets"
    buildPackets siz [spkt] build0 build1 = do
        bss <- encodePlainPacket conn (spPlainPacket spkt) $ Just siz
        let sentPacket = fixSentPacket spkt bss True
        return (build0 [sentPacket], build1 bss)
    buildPackets siz (spkt:ss) build0 build1 = do
        bss <- encodePlainPacket conn (spPlainPacket spkt) Nothing
        let sentPacket = fixSentPacket spkt bss False
        let build0' = build0 . (sentPacket :)
            build1' = build1 . (bss ++)
            siz' = siz - spSentBytes sentPacket
        buildPackets siz' ss build0' build1'

----------------------------------------------------------------

sendPingPacket :: Connection -> SendMany -> EncryptionLevel -> IO ()
sendPingPacket conn send lvl = do
    maxSiz <- getMaxPacketSize conn
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
    xs <- construct conn lvl frames
    if null xs then
        qlogDebug conn $ Debug "ping NULL"
      else do
        let spkt = last xs
            ping = spPlainPacket spkt
        bss <- encodePlainPacket conn ping (Just maxSiz)
        now <- getTimeMicrosecond
        send bss
        addTxBytes conn $ totalLen bss
        let sentPacket0 = fixSentPacket spkt bss True
            sentPacket = sentPacket0 { spTimeSent = now }
        qlogSent conn sentPacket now
        onPacketSent ldcc sentPacket

----------------------------------------------------------------

construct :: Connection
          -> EncryptionLevel
          -> [Frame]
          -> IO [SentPacket]
construct conn lvl frames = do
    discarded <- getPacketNumberSpaceDiscarded ldcc lvl
    if discarded then
        return []
      else do
        established <- isConnectionEstablished conn
        if established || (isServer conn && lvl == HandshakeLevel) then do
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
              RTT1Level      -> HandshakeLevel
              _              -> RTT1Level
        if lvl' == RTT1Level then
            return []
          else do
            ppns <- getPeerPacketNumbers ldcc lvl'
            if nullPeerPacketNumbers ppns then
                return []
              else do
                let ackFrame = Ack (toAckInfo $ fromPeerPacketNumbers ppns) 0
                (ppkt, mypn) <- mkPlainPacket conn lvl' [ackFrame]
                return [mkSentPacket mypn lvl' ppkt ppns False]
    constructTargetPacket
      | null frames = do -- ACK only packet
            resetDealyedAck conn
            ppns <- getPeerPacketNumbers ldcc lvl
            if nullPeerPacketNumbers ppns then
                return []
              else
                if lvl == RTT1Level then do
                    prevppns <- getPreviousRTT1PPNs ldcc
                    if ppns /= prevppns then do
                        setPreviousRTT1PPNs ldcc ppns
                        (ppkt, mypn) <- mkAckPlainPacket conn lvl ppns
                        return [mkSentPacket mypn lvl ppkt ppns False]
                     else
                       return []
                  else do
                    (ppkt, mypn) <- mkAckPlainPacket conn lvl ppns
                    return [mkSentPacket mypn lvl ppkt ppns False]
      | otherwise = do
            resetDealyedAck conn
            ppns <- getPeerPacketNumbers ldcc lvl
            let frames' | nullPeerPacketNumbers ppns = frames
                        | otherwise                  = mkAck ppns : frames
            (ppkt, mypn) <- mkPlainPacket conn lvl frames'
            return [mkSentPacket mypn lvl ppkt ppns True]

mkAck :: PeerPacketNumbers -> Frame
mkAck ppns = Ack (toAckInfo $ fromPeerPacketNumbers ppns) 0

mkAckPlainPacket :: Connection -> EncryptionLevel -> PeerPacketNumbers -> IO (PlainPacket, PacketNumber)
mkAckPlainPacket conn lvl ppns =
    mkPlainPacket conn lvl frames
 where
   frames = mkAck ppns : []

mkPlainPacket :: Connection -> EncryptionLevel -> [Frame] -> IO (PlainPacket, PacketNumber)
mkPlainPacket conn lvl frames = do
    header <- mkHeader conn lvl
    mypn <- nextPacketNumber conn
    let plain = Plain (Flags 0) mypn frames
        ppkt = PlainPacket header plain
    return (ppkt, mypn)

mkHeader :: Connection -> EncryptionLevel -> IO Header
mkHeader conn lvl = do
    ver <- getVersion conn
    mycid <- getMyCID conn
    peercid <- getPeerCID conn
    token <- if lvl == InitialLevel then getToken conn else return ""
    return $ case lvl of
      InitialLevel   -> Initial   ver peercid mycid token
      RTT0Level      -> RTT0      ver peercid mycid
      HandshakeLevel -> Handshake ver peercid mycid
      RTT1Level      -> Short         peercid

----------------------------------------------------------------

data Switch = SwPing EncryptionLevel
            | SwBlck Blocked
            | SwOut  Output
            | SwStrm TxStreamData

sender :: Connection -> SendMany -> IO ()
sender conn send = handleLog logAction $ forever $ do
    x <- atomically ((SwPing <$> takePingSTM (connLDCC conn))
            `orElse` (SwBlck <$> takeSendBlockQSTM conn)
            `orElse` (SwOut  <$> takeOutputSTM conn)
            `orElse` (SwStrm <$> takeSendStreamQSTM conn))
    case x of
      SwPing lvl -> sendPingPacket conn send lvl
      SwBlck blk -> sendBlocked conn send blk
      SwOut  out -> sendOutput conn send out
      SwStrm tx  -> sendTxStreamData conn send tx
  where
    logAction msg = connDebugLog conn ("sender: " <> msg)

----------------------------------------------------------------

sendBlocked :: Connection -> SendMany -> Blocked -> IO ()
sendBlocked conn send blocked = do
    let frames = case blocked of
          StrmBlocked strm n -> [StreamDataBlocked (streamId strm) n]
          ConnBlocked n      -> [DataBlocked n]
          BothBlocked strm n m -> [StreamDataBlocked (streamId strm) n, DataBlocked m]
    construct conn RTT1Level frames >>= sendPacket conn send

----------------------------------------------------------------

discardInitialPacketNumberSpace :: Connection -> IO ()
discardInitialPacketNumberSpace conn
  | isClient conn = do
        let ldcc = connLDCC conn
        discarded <- getPacketNumberSpaceDiscarded ldcc InitialLevel
        unless discarded $ do
            dropSecrets conn InitialLevel
            clearCryptoStream conn InitialLevel
            onPacketNumberSpaceDiscarded ldcc InitialLevel
  | otherwise = return ()

sendOutput :: Connection -> SendMany -> Output -> IO ()
sendOutput conn send (OutControl lvl frames) = do
    construct conn lvl frames >>= sendPacket conn send
    when (lvl == HandshakeLevel) $ discardInitialPacketNumberSpace conn
sendOutput conn send (OutHandshake x) = do
    sendCryptoFragments conn send x
sendOutput conn send (OutRetrans (PlainPacket hdr0 plain0)) = do
    frames <- adjustForRetransmit conn $ plainFrames plain0
    let lvl = levelFromHeader hdr0
    construct conn lvl frames >>= sendPacket conn send

levelFromHeader :: Header -> EncryptionLevel
levelFromHeader hdr
    | lvl == RTT0Level = RTT1Level
    | otherwise        = lvl
  where
    lvl = packetEncryptionLevel hdr

adjustForRetransmit :: Connection -> [Frame] -> IO [Frame]
adjustForRetransmit _    [] = return []
adjustForRetransmit conn (Padding{}:xs) = adjustForRetransmit conn xs
adjustForRetransmit conn (Ack{}:xs)     = adjustForRetransmit conn xs
adjustForRetransmit conn (MaxStreamData sid _:xs) = do
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> adjustForRetransmit conn xs
      Just strm -> do
          newMax <- getRxMaxStreamData strm
          let r = MaxStreamData sid newMax
          rs <- adjustForRetransmit conn xs
          return (r : rs)
adjustForRetransmit conn (MaxData{}:xs) = do
    newMax <- getRxMaxData conn
    let r = MaxData newMax
    rs <- adjustForRetransmit conn xs
    return (r : rs)
adjustForRetransmit conn (x:xs) = do
    rs <- adjustForRetransmit conn xs
    return (x : rs)

sendTxStreamData :: Connection -> SendMany -> TxStreamData -> IO ()
sendTxStreamData conn send tx@(TxStreamData _ _ len _) = do
    addTxData conn len
    sendStreamFragment conn send tx

limitationC :: Int
limitationC = 1024

thresholdC :: Int
thresholdC = 200

sendCryptoFragments :: Connection -> SendMany -> [(EncryptionLevel, CryptoData)] -> IO ()
sendCryptoFragments conn send lcs = do
    loop limitationC id lcs
    when (any (\(l,_) -> l == HandshakeLevel) lcs) $
        discardInitialPacketNumberSpace conn
  where
    loop :: Int -> ([SentPacket] -> [SentPacket]) -> [(EncryptionLevel, CryptoData)] -> IO ()
    loop _ build0 [] = do
        let spkts0 = build0 []
        unless (null spkts0) $ sendPacket conn send spkts0
    loop len0 build0 ((lvl, bs) : xs) | B.length bs > len0 = do
        let (target, rest) = B.splitAt len0 bs
        frame1 <- cryptoFrame conn target lvl
        spkts1 <- construct conn lvl [frame1]
        sendPacket conn send $ build0 spkts1
        loop limitationC id ((lvl, rest) : xs)
    loop _ build0 [(lvl, bs)] = do
        frame1 <- cryptoFrame conn bs lvl
        spkts1 <- construct conn lvl [frame1]
        sendPacket conn send $ build0 spkts1
    loop len0 build0 ((lvl, bs) : xs) | len0 - B.length bs < thresholdC = do
        frame1 <- cryptoFrame conn bs lvl
        spkts1 <- construct conn lvl [frame1]
        sendPacket conn send $ build0 spkts1
        loop limitationC id xs
    loop len0 build0 ((lvl, bs) : xs) = do
        frame1 <- cryptoFrame conn bs lvl
        spkts1 <- construct conn lvl [frame1]
        let len1 = len0 - B.length bs
            build1 = build0 . (spkts1 ++)
        loop len1  build1 xs

----------------------------------------------------------------

threshold :: Int
threshold  =  832

limitation :: Int
limitation = 1040

packFin :: Stream -> Bool -> IO Bool
packFin _ True  = return True
packFin s False = do
    mx <- tryPeekSendStreamQ s
    case mx of
      Just (TxStreamData s1 [] 0 True)
          | streamId s == streamId s1 -> do
                _ <- takeSendStreamQ s
                return True
      _ -> return False

sendStreamFragment :: Connection -> SendMany -> TxStreamData -> IO ()
sendStreamFragment conn send (TxStreamData s dats len fin0) = do
    fin <- packFin s fin0
    if len < limitation then do
        sendStreamSmall conn send s dats fin len
      else
        sendStreamLarge conn send s dats fin

sendStreamSmall :: Connection -> SendMany -> Stream -> [StreamData] -> Bool -> Int -> IO ()
sendStreamSmall conn send s0 dats0 fin0 len0 = do
    off0 <- getTxStreamOffset s0 len0
    let sid0 = streamId s0
        frame0 = StreamF sid0 off0 dats0 fin0
    frames <- loop s0 frame0 len0 id
    ready <- isConnection1RTTReady conn
    let lvl | ready     = RTT1Level
            | otherwise = RTT0Level
    construct conn lvl frames >>= sendPacket conn send
  where
    tryPeek = do
        mx <- tryPeekSendStreamQ s0
        case mx of
          Nothing -> do
              yield
              tryPeekSendStreamQ s0
          Just _ -> return mx
    loop :: Stream -> Frame -> Int -> ([Frame] -> [Frame]) -> IO [Frame]
    loop s frame total build = do
        mx <- tryPeek
        case mx of
          Nothing -> return $ build [frame]
          Just (TxStreamData s1 dats1 len1 fin1) -> do
              let total1 = len1 + total
              if total1 < limitation then do
                  _ <- takeSendStreamQ s0 -- cf tryPeek
                  addTxData conn len1
                  fin1' <- packFin s fin1 -- must be after takeSendStreamQ
                  off1 <- getTxStreamOffset s1 len1
                  let sid  = streamId s
                      sid1 = streamId s1
                  if sid == sid1 then do
                      let StreamF _ off dats _ = frame
                          frame1 = StreamF sid off (dats ++ dats1) fin1'
                      loop s1 frame1 total1 build
                    else do
                      let frame1 = StreamF sid1 off1 dats1 fin1'
                          build1 = build . (frame :)
                      loop s1 frame1 total1 build1
                else
                  return $ build [frame]

sendStreamLarge :: Connection -> SendMany -> Stream -> [ByteString] -> Bool -> IO ()
sendStreamLarge conn send s dats0 fin0 = loop dats0
  where
    sid = streamId s
    loop [] = return ()
    loop dats = do
        let (dats1,dats2) = splitChunks dats
            len = totalLen dats1
        off <- getTxStreamOffset s len
        let fin = fin0 && null dats2
            frame = StreamF sid off dats1 fin
        ready <- isConnection1RTTReady conn
        let lvl | ready     = RTT1Level
                | otherwise = RTT0Level
        construct conn lvl [frame] >>= sendPacket conn send
        loop dats2

-- Typical case: [3, 1024, 1024, 1024, 200]
splitChunks :: [ByteString] -> ([ByteString],[ByteString])
splitChunks bs0 = loop bs0 0 id
  where
    loop [] _  build    = let curr = build [] in (curr, [])
    loop bbs@(b:bs) siz0 build
      | siz <= threshold  = let build' = build . (b :) in loop bs siz build'
      | siz <= limitation = let curr = build [b] in (curr, bs)
      | len >  limitation = let (u,b') = B.splitAt (limitation - siz0) b
                                curr = build [u]
                                bs' = b':bs
                            in (curr,bs')
      | otherwise         = let curr = build [] in (curr, bbs)
      where
        len = B.length b
        siz = siz0 + len
