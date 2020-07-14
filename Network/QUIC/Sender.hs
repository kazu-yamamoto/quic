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

construct :: Connection
          -> EncryptionLevel
          -> [Frame]
          -> Maybe Int       -- Packet size
          -> IO [ByteString]
construct conn lvl frames mTargetSize = do
    ver <- getVersion conn
    token <- getToken conn
    mycid <- getMyCID conn
    peercid <- getPeerCID conn
    established <- isConnectionEstablished conn
    if established || (isServer conn && lvl == HandshakeLevel) then
        constructTargetPacket ver mycid peercid mTargetSize token
      else do
        bss0 <- constructLowerAckPacket lvl ver mycid peercid token
        let total = totalLen bss0
            mTargetSize' = subtract total <$> mTargetSize
        bss1 <- constructTargetPacket ver mycid peercid mTargetSize' token
        return (bss0 ++ bss1)
  where
    constructLowerAckPacket HandshakeLevel ver mycid peercid token = do
        ppns <- getPeerPacketNumbers conn InitialLevel
        if nullPeerPacketNumbers ppns then
            return []
          else do
            -- This packet will not be acknowledged.
            clearPeerPacketNumbers conn InitialLevel
            mypn <- getPacketNumber conn
            let header   = Initial ver peercid mycid token
                ackFrame = Ack (toAckInfo $ fromPeerPacketNumbers ppns) 0
                plain    = Plain (Flags 0) mypn [ackFrame]
                ppkt     = PlainPacket header plain
            qlogSent conn ppkt
            encodePlainPacket conn ppkt Nothing
    constructLowerAckPacket RTT1Level ver mycid peercid _ = do
        ppns <- getPeerPacketNumbers conn HandshakeLevel
        if nullPeerPacketNumbers ppns then
            return []
          else do
            -- This packet will not be acknowledged.
            clearPeerPacketNumbers conn HandshakeLevel
            mypn <- getPacketNumber conn
            let header   = Handshake ver peercid mycid
                ackFrame = Ack (toAckInfo $ fromPeerPacketNumbers ppns) 0
                plain    = Plain (Flags 0) mypn [ackFrame]
                ppkt     = PlainPacket header plain
            qlogSent conn ppkt
            encodePlainPacket conn ppkt Nothing
    constructLowerAckPacket _ _ _ _ _ = return []
    constructTargetPacket ver mycid peercid mlen token
      | null frames = do -- ACK only packet
            ppns <- getPeerPacketNumbers conn lvl -- don't clear
            if nullPeerPacketNumbers ppns then
                return []
              else do
                mypn <- getPacketNumber conn
                let frames' = [toAck ppns]
                    plain = toPlain mypn frames'
                    ppkt = toPlainPakcet lvl plain
                -- don't keep this ppkt
                qlogSent conn ppkt
                encodePlainPacket conn ppkt mlen
      | otherwise = do
            -- If packets are acked only once, packet loss of ACKs
            -- causes spurious retransmits. So, Packets should be
            -- acked mutliple times. For this purpose,
            -- peerPacketNumber is not clear here. See section 13.2.3
            -- of transport.
            ppns <- getPeerPacketNumbers conn lvl -- don't clear
            let frames' | nullPeerPacketNumbers ppns = frames
                        | otherwise                  = toAck ppns : frames
            mypn <- getPacketNumber conn
            let plain = toPlain mypn frames'
                ppkt = toPlainPakcet lvl plain
                sentBytes = fromMaybe 0 mTargetSize -- fixme
            waitWindowOpen conn sentBytes >>= print
            onPacketSent conn lvl mypn ppkt ppns sentBytes -- keep
            qlogSent conn ppkt
            encodePlainPacket conn ppkt mlen
      where
        toAck ppns = Ack (toAckInfo $ fromPeerPacketNumbers ppns) 0
        toPlain mypn fs = Plain (Flags 0) mypn fs'
          where
            fs' = case mlen of
              Nothing -> fs
              Just _  -> fs ++ [Padding 0] -- for qlog
        toPlainPakcet InitialLevel   plain =
            PlainPacket (Initial   ver peercid mycid token) plain
        toPlainPakcet RTT0Level      plain =
            PlainPacket (RTT0      ver peercid mycid)       plain
        toPlainPakcet HandshakeLevel plain =
            PlainPacket (Handshake ver peercid mycid)       plain
        toPlainPakcet RTT1Level      plain =
            PlainPacket (Short         peercid)             plain

----------------------------------------------------------------

sender :: Connection -> SendMany -> IO ()
sender conn send = handleLog logAction $ forever $ do
    ex <- atomically ((Left  <$> takeOutputSTM conn)
             `orElse` (Right <$> takeSendStreamQSTM conn))
    case ex of
      Left  out -> sendOutput conn send out
      Right tx  -> sendTxStreamData conn send tx
  where
    logAction msg = connDebugLog conn ("sender: " <> msg)

sendOutput :: Connection -> SendMany -> Output -> IO ()
sendOutput conn send (OutControl lvl frames) = do
    maxSiz <- getMaxPacketSize conn
    construct conn lvl frames (Just maxSiz) >>= send
sendOutput conn send (OutHandshake x) = do
    maxSiz <- getMaxPacketSize conn
    sendCryptoFragments conn send maxSiz x
sendOutput conn send (OutRetrans (PlainPacket hdr0 plain0)) = do
    let lvl = packetEncryptionLevel hdr0
    let frames = filter retransmittable $ plainFrames plain0
    maxSiz <- getMaxPacketSize conn
    construct conn lvl frames (Just maxSiz) >>= send

sendTxStreamData :: Connection -> SendMany -> TxStreamData -> IO ()
sendTxStreamData conn send tx@(TxStreamData _ _ len _) = do
    addTxData conn len
    maxSiz <- getMaxPacketSize conn
    sendStreamFragment conn send maxSiz tx

limitationC :: Int
limitationC = 1024

thresholdC :: Int
thresholdC = 200

sendCryptoFragments :: Connection -> SendMany -> Int -> [(EncryptionLevel, CryptoData)] -> IO ()
sendCryptoFragments conn send maxSiz = loop limitationC maxSiz id
  where
    loop _ _ build0 [] = do
        let bss0 = build0 []
        unless (null bss0) $ send bss0
    loop len0 siz0 build0 ((lvl, bs) : xs) | B.length bs > len0 = do
        let (target, rest) = B.splitAt len0 bs
        frame1 <- cryptoFrame conn target lvl
        bss1 <- construct conn lvl [frame1] $ Just siz0
        send $ build0 bss1
        loop limitationC maxSiz id ((lvl, rest) : xs)
    loop _ siz0 build0 ((lvl, bs) : []) = do
        frame1 <- cryptoFrame conn bs lvl
        bss1 <- construct conn lvl [frame1] $ Just siz0
        send $ build0 bss1
    loop len0 siz0 build0 ((lvl, bs) : xs) | len0 - B.length bs < thresholdC = do
        frame1 <- cryptoFrame conn bs lvl
        bss1 <- construct conn lvl [frame1] $ Just siz0
        send $ build0 bss1
        loop limitationC maxSiz id xs
    loop len0 siz0 build0 ((lvl, bs) : xs) = do
        frame1 <- cryptoFrame conn bs lvl
        bss1 <- construct conn lvl [frame1] Nothing
        let len1 = len0 - B.length bs
            siz1 = siz0 - totalLen bss1
            build1 = build0 . (bss1 ++)
        loop len1 siz1 build1 xs

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

sendStreamFragment :: Connection -> SendMany -> Int -> TxStreamData -> IO ()
sendStreamFragment conn send maxSiz (TxStreamData s dats len fin0) = do
    let sid = streamId s
    fin <- packFin s fin0
    if len < limitation then do
        off <- getTxStreamOffset s len
        let frame = StreamF sid off dats fin
        sendStreamSmall conn send s frame len maxSiz
      else
        sendStreamLarge conn send s dats fin maxSiz
    when fin $ setTxStreamFin s

sendStreamSmall :: Connection -> SendMany -> Stream -> Frame -> Int -> Int -> IO ()
sendStreamSmall conn send s0 frame0 total0 maxSiz = do
    frames <- loop s0 frame0 total0 id
    ready <- isConnection1RTTReady conn
    let lvl | ready     = RTT1Level
            | otherwise = RTT0Level
    construct conn lvl frames (Just maxSiz) >>= send
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

sendStreamLarge :: Connection -> SendMany -> Stream -> [ByteString] -> Bool -> Int -> IO ()
sendStreamLarge conn send s dats0 fin0 maxSiz = loop fin0 dats0
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
        construct conn lvl [frame] (Just maxSiz) >>= send
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
