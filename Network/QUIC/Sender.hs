{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Sender (
    sender
  ) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Data.ByteString as B

import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
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

sendPacket :: Connection -> SendMany -> [SentPacketI] -> IO ()
sendPacket _ _ [] = return ()
sendPacket conn send spktis = getMaxPacketSize conn >>= go
  where
    go maxSiz = do
        mx <- atomically ((Just    <$> takePingSTM conn)
                 `orElse` (Nothing <$  checkWindowOpenSTM conn maxSiz))
        when (isJust mx) $ qlogDebug conn $ Debug "probe sent"
        (sentPackets, bss) <- loop maxSiz spktis id id
        -- w <- getRandomOneByte
        -- let dropPacket = (w `mod` 20) == 0
        let dropPacket = False
        if dropPacket then do
            putStrLn $ "Randomly dropped: " ++ show (map spPacketNumber spktis)
            qlogDebug conn $ Debug "randomly dropped"
          else
            send bss
        forM_ sentPackets $ \x -> do
            unless dropPacket $ qlogSent conn x
            onPacketSent conn x
    loop _ [] _ _ = error "sendPacket: loop"
    loop siz [spkti] build0 build1 = do
        bss <- encodePlainPacket conn (spPlainPacket spkti) $ Just siz
        now <- getTimeMicrosecond
        let sentBytes = totalLen bss
        let sentPacket = SentPacket {
                spSentPacketI  = addPadding spkti
              , spTimeSent     = now
              , spSentBytes    = sentBytes
              }
        return (build0 [sentPacket], build1 bss)
    loop siz (spkti:ss) build0 build1 = do
        bss <- encodePlainPacket conn (spPlainPacket spkti) Nothing
        now <- getTimeMicrosecond
        let sentBytes = totalLen bss
        let sentPacket = SentPacket {
                spSentPacketI  = spkti
              , spTimeSent     = now
              , spSentBytes    = sentBytes
              }
        let build0' = (build0 . (sentPacket :))
            build1' = build1 . (bss ++)
            siz' = siz - sentBytes
        loop siz' ss build0' build1'

addPadding :: SentPacketI -> SentPacketI
addPadding spi = spi {
      spPlainPacket = modify $ spPlainPacket spi
    }
  where
    modify (PlainPacket hdr plain) = PlainPacket hdr plain'
      where
        plain' = plain {
          plainFrames = plainFrames plain ++ [Padding 0]
        }

----------------------------------------------------------------

construct :: Connection
          -> EncryptionLevel
          -> [Frame]
          -> IO [SentPacketI]
construct conn lvl frames = do
    ver <- getVersion conn
    token <- getToken conn
    mycid <- getMyCID conn
    peercid <- getPeerCID conn
    established <- isConnectionEstablished conn
    if established || (isServer conn && lvl == HandshakeLevel) then do
        constructTargetPacket ver mycid peercid token
      else do
        ppkt0 <- constructLowerAckPacket ver mycid peercid token
        ppkt1 <- constructTargetPacket ver mycid peercid token
        return (ppkt0 ++ ppkt1)
  where
    constructLowerAckPacket ver mycid peercid token = do
        let lvl' = case lvl of
              HandshakeLevel -> InitialLevel
              RTT1Level      -> HandshakeLevel
              _              -> RTT1Level
        if lvl' == RTT1Level then
            return []
          else do
            ppns <- getPeerPacketNumbers conn lvl'
            if nullPeerPacketNumbers ppns then
                return []
              else do
                mypn <- getPacketNumber conn
                -- clearPeerPacketNumbers should be called in
                -- Connection.Recovery. However, this is a necessary
                -- workaround to not send ACK which the peer cannot
                -- decrypt.
                clearPeerPacketNumbers conn lvl'
                let header
                      | lvl' == InitialLevel = Initial   ver peercid mycid token
                      | otherwise            = Handshake ver peercid mycid
                    ackFrame = Ack (toAckInfo $ fromPeerPacketNumbers ppns) 0
                    plain    = Plain (Flags 0) mypn [ackFrame]
                    ppkt     = PlainPacket header plain
                return [SentPacketI mypn lvl' ppkt ppns False]
    constructTargetPacket ver mycid peercid token
      | null frames = do -- ACK only packet
            resetDealyedAck conn
            ppns <- getPeerPacketNumbers conn lvl
            if nullPeerPacketNumbers ppns then
                return []
              else do
                mypn <- getPacketNumber conn
                let frames' = [toAck ppns]
                    plain = Plain (Flags 0) mypn frames'
                    ppkt = toPlainPakcet lvl plain
                return [SentPacketI mypn lvl ppkt ppns False]
      | otherwise = do
            -- If packets are acked only once, packet loss of ACKs
            -- causes spurious retransmits. So, Packets should be
            -- acked mutliple times. For this purpose,
            -- peerPacketNumber is not clear here. See section 13.2.3
            -- of transport.
            resetDealyedAck conn
            ppns <- getPeerPacketNumbers conn lvl
            let frames' | nullPeerPacketNumbers ppns = frames
                        | otherwise                  = toAck ppns : frames
            mypn <- getPacketNumber conn
            let plain = Plain (Flags 0) mypn frames'
                ppkt = toPlainPakcet lvl plain
            return [SentPacketI mypn lvl ppkt ppns True]
      where
        toAck ppns = Ack (toAckInfo $ fromPeerPacketNumbers ppns) 0
        toPlainPakcet InitialLevel   plain =
            PlainPacket (Initial   ver peercid mycid token) plain
        toPlainPakcet RTT0Level      plain =
            PlainPacket (RTT0      ver peercid mycid)       plain
        toPlainPakcet HandshakeLevel plain =
            PlainPacket (Handshake ver peercid mycid)       plain
        toPlainPakcet RTT1Level      plain =
            PlainPacket (Short         peercid)             plain

----------------------------------------------------------------

data Switch = SwPing EncryptionLevel
            | SwBlck Blocked
            | SwOut  Output
            | SwStrm TxStreamData

sender :: Connection -> SendMany -> IO ()
sender conn send = handleLog logAction $ forever $ do
    x <- atomically ((SwPing <$> takePingSTM conn)
            `orElse` (SwBlck <$> takeSendBlockQSTM conn)
            `orElse` (SwOut  <$> takeOutputSTM conn)
            `orElse` (SwStrm <$> takeSendStreamQSTM conn))
    case x of
      SwPing lvl -> sendPing conn send lvl
      SwBlck blk -> sendBlocked conn send blk
      SwOut  out -> sendOutput conn send out
      SwStrm tx  -> sendTxStreamData conn send tx
  where
    logAction msg = connDebugLog conn ("sender: " <> msg)

----------------------------------------------------------------

sendPing :: Connection -> SendMany -> EncryptionLevel -> IO ()
sendPing conn send lvl = do
    maxSiz <- getMaxPacketSize conn
    xs <- construct conn lvl [Ping]
    let spkti = last xs
        ping = spPlainPacket spkti
    bss <- encodePlainPacket conn ping (Just maxSiz)
    send bss
    now <- getTimeMicrosecond
    let siz = totalLen bss
        spkt = SentPacket spkti now siz
    qlogSent conn spkt

----------------------------------------------------------------

sendBlocked :: Connection -> SendMany -> Blocked -> IO ()
sendBlocked conn send blocked = do
    let frames = case blocked of
          StrmBlocked strm n -> [StreamDataBlocked (streamId strm) n]
          ConnBlocked n      -> [DataBlocked n]
          BothBlocked strm n m -> [StreamDataBlocked (streamId strm) n, DataBlocked m]
    construct conn RTT1Level frames >>= sendPacket conn send

----------------------------------------------------------------

sendOutput :: Connection -> SendMany -> Output -> IO ()
sendOutput conn send (OutControl lvl frames) = do
    construct conn lvl frames >>= sendPacket conn send
sendOutput conn send (OutHandshake x) = do
    sendCryptoFragments conn send x
sendOutput conn send (OutRetrans (PlainPacket hdr0 plain0)) = do
    let lvl0 = packetEncryptionLevel hdr0
    let lvl | lvl0 == RTT0Level = RTT1Level
            | otherwise         = lvl0
    frames <- adjustForRetransmit conn $ plainFrames plain0
    -- Ping coems here because it is ack-eliciting.
    -- But it results in null frames.
    unless (null frames) $
        construct conn lvl frames >>= sendPacket conn send

adjustForRetransmit :: Connection -> [Frame] -> IO [Frame]
adjustForRetransmit _    [] = return []
adjustForRetransmit conn (Padding{}:xs) = adjustForRetransmit conn xs
adjustForRetransmit conn (Ack{}:xs)     = adjustForRetransmit conn xs
adjustForRetransmit conn (Ping{}:xs)    = adjustForRetransmit conn xs
adjustForRetransmit conn (MaxStreamData sid _:xs) = do
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> adjustForRetransmit conn xs
      Just strm -> do
          newMax <- addRxMaxStreamData strm 0
          let r = MaxStreamData sid newMax
          rs <- adjustForRetransmit conn xs
          return (r : rs)
adjustForRetransmit conn (MaxData{}:xs) = do
    newMax <- addRxMaxData conn 0
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
    when (isClient conn && any (\(l,_) -> l == HandshakeLevel) lcs) $ do
        dropSecrets conn InitialLevel
        onPacketNumberSpaceDiscarded conn InitialLevel
  where
    loop :: Int -> ([SentPacketI] -> [SentPacketI]) -> [(EncryptionLevel, CryptoData)] -> IO ()
    loop _ build0 [] = do
        let bss0 = build0 []
        unless (null bss0) $ sendPacket conn send bss0
    loop len0 build0 ((lvl, bs) : xs) | B.length bs > len0 = do
        let (target, rest) = B.splitAt len0 bs
        frame1 <- cryptoFrame conn target lvl
        bss1 <- construct conn lvl [frame1]
        sendPacket conn send $ build0 bss1
        loop limitationC id ((lvl, rest) : xs)
    loop _ build0 ((lvl, bs) : []) = do
        frame1 <- cryptoFrame conn bs lvl
        bss1 <- construct conn lvl [frame1]
        sendPacket conn send $ build0 bss1
    loop len0 build0 ((lvl, bs) : xs) | len0 - B.length bs < thresholdC = do
        frame1 <- cryptoFrame conn bs lvl
        bss1 <- construct conn lvl [frame1]
        sendPacket conn send $ build0 bss1
        loop limitationC id xs
    loop len0 build0 ((lvl, bs) : xs) = do
        frame1 <- cryptoFrame conn bs lvl
        bss1 <- construct conn lvl [frame1]
        let len1 = len0 - B.length bs
            build1 = build0 . (bss1 ++)
        loop len1  build1 xs

----------------------------------------------------------------

threshold :: Int
threshold  =  832

limitation :: Int
limitation = 1040

totalLen :: [ByteString] -> Int
totalLen = sum . map B.length

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
    let sid = streamId s
    fin <- packFin s fin0
    if len < limitation then do
        off <- getTxStreamOffset s len
        let frame = StreamF sid off dats fin
        sendStreamSmall conn send s frame len
      else
        sendStreamLarge conn send s dats fin
    when fin $ setTxStreamFin s

sendStreamSmall :: Connection -> SendMany -> Stream -> Frame -> Int -> IO ()
sendStreamSmall conn send s0 frame0 total0 = do
    frames <- loop s0 frame0 total0 id
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
                  when fin1' $ setTxStreamFin s1
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
sendStreamLarge conn send s dats0 fin0 = loop fin0 dats0
  where
    sid = streamId s
    loop _ [] = return ()
    loop fin dats = do
        let (dats1,dats2) = splitChunks dats
            len = totalLen dats1
        off <- getTxStreamOffset s len
        let fin1 = fin && null dats2
            frame = StreamF sid off dats1 fin1
        ready <- isConnection1RTTReady conn
        let lvl | ready     = RTT1Level
                | otherwise = RTT0Level
        construct conn lvl [frame] >>= sendPacket conn send
        loop fin dats2

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
