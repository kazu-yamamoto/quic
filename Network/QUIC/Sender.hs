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
        case mx of
          Just lvl | lvl `elem` [InitialLevel,HandshakeLevel] -> do
            sendPing conn send lvl
            go maxSiz
          _ -> do
            when (isJust mx) $ qlogDebug conn $ Debug "probe new"
            (sentPackets, bss) <- buildPackets maxSiz spktis id id
            send bss
            forM_ sentPackets $ \x -> do
                qlogSent conn x
                onPacketSent conn x
    buildPackets _ [] _ _ = error "sendPacket: buildPackets"
    buildPackets siz [spkti] build0 build1 = do
        bss <- encodePlainPacket conn (spPlainPacket spkti) $ Just siz
        now <- getTimeMicrosecond
        let sentBytes = totalLen bss
        let sentPacket = SentPacket {
                spSentPacketI  = addPadding spkti
              , spTimeSent     = now
              , spSentBytes    = sentBytes
              }
        return (build0 [sentPacket], build1 bss)
    buildPackets siz (spkti:ss) build0 build1 = do
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
        buildPackets siz' ss build0' build1'

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
    discarded <- getPacketNumberSpaceDiscarded conn lvl
    if discarded then
        return []
      else do
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
                if lvl == RTT1Level then do
                    prevppns <- getPreviousRTT1PPNs conn
                    if ppns /= prevppns then do
                        setPreviousRTT1PPNs conn ppns
                        let frames' = [toAck ppns]
                            plain = Plain (Flags 0) mypn frames'
                            ppkt = toPlainPakcet lvl plain
                        return [SentPacketI mypn lvl ppkt ppns False]
                     else
                       return []
                  else do
                    let frames' = [toAck ppns]
                        plain = Plain (Flags 0) mypn frames'
                        ppkt = toPlainPakcet lvl plain
                    return [SentPacketI mypn lvl ppkt ppns False]
      | otherwise = do
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
    mp <- releaseOldest conn lvl
    frames <- case mp of
      Nothing -> do
          qlogDebug conn $ Debug "probe ping"
          return [Ping]
      Just spkt -> do
          qlogDebug conn $ Debug "probe old"
          let PlainPacket _ plain0 = spPlainPacket $ spSentPacketI spkt
          adjustForRetransmit conn $ plainFrames plain0
    xs <- construct conn lvl frames
    let spkti = last xs
        ping = spPlainPacket spkti
    bss <- encodePlainPacket conn ping (Just maxSiz)
    send bss
    now <- getTimeMicrosecond
    let siz = totalLen bss
        spkt = SentPacket spkti now siz
    qlogSent conn spkt
    onPacketSent conn spkt

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
        discarded <- getPacketNumberSpaceDiscarded conn InitialLevel
        unless discarded $ do
            dropSecrets conn InitialLevel
            onPacketNumberSpaceDiscarded conn InitialLevel
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
    when (any (\(l,_) -> l == HandshakeLevel) lcs) $
        discardInitialPacketNumberSpace conn
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
