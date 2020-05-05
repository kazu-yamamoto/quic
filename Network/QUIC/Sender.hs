{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Sender (
    sender
  , resender
  ) where

import Control.Concurrent
import qualified Data.ByteString as B
import Data.IORef

import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Types

----------------------------------------------------------------

cryptoFrame :: Connection -> CryptoData -> EncryptionLevel -> IO Frame
cryptoFrame conn crypto lvl = do
    let len = B.length crypto
    off <- getCryptoOffset conn lvl len
    return $ Crypto off crypto

----------------------------------------------------------------

construct :: Connection
          -> EncryptionLevel
          -> [Frame]
          -> [PacketNumber]  -- Packet number history
          -> Maybe Int       -- Packet size
          -> IO [ByteString]
construct conn lvl frames pns mTargetSize = do
    ver <- getVersion conn
    token <- getToken conn
    mycid <- getMyCID conn
    peercid <- getPeerCID conn
    established <- isConnectionEstablished conn
    if established || (isServer conn && lvl == HandshakeLevel) then
        constructTargetPacket ver mycid peercid mTargetSize token
      else do
        bss0 <- constructLowerAckPacket lvl ver mycid peercid token
        let total = sum (map B.length bss0)
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
    constructTargetPacket ver mycid peercid mlen token = do
        mypn <- getPacketNumber conn
        ppns <- getPeerPacketNumbers conn lvl
        let frames'
              | nullPeerPacketNumbers ppns = frames
              | otherwise   = Ack (toAckInfo $ fromPeerPacketNumbers ppns) 0 : frames
        let frames'' = case mlen of
              Nothing -> frames'
              Just _  -> frames' ++ [Padding 0] -- for qlog
        let ppkt = case lvl of
              InitialLevel   -> PlainPacket (Initial   ver peercid mycid token) (Plain (Flags 0) mypn frames'')
              RTT0Level      -> PlainPacket (RTT0      ver peercid mycid)       (Plain (Flags 0) mypn frames'')
              HandshakeLevel -> PlainPacket (Handshake ver peercid mycid)       (Plain (Flags 0) mypn frames'')
              RTT1Level      -> PlainPacket (Short         peercid)             (Plain (Flags 0) mypn frames'')
        if any ackEliciting frames then
            keepPlainPacket conn (mypn:pns) ppkt lvl ppns
          else
            clearPeerPacketNumbers conn lvl
        qlogSent conn ppkt
        encodePlainPacket conn ppkt mlen

----------------------------------------------------------------

sender :: Connection -> SendMany -> IO ()
sender conn send = handleLog logAction $ forever
    (takeOutput conn >>= sendOutput conn send)
  where
    logAction msg = connDebugLog conn ("sender: " ++ msg)

sendOutput :: Connection -> SendMany -> Output ->IO ()
sendOutput conn send (OutHandshake x) = sendCryptoFragments conn send x
sendOutput conn send (OutControl lvl frames) = do
    bss <- construct conn lvl frames [] $ Just maximumQUICPacketSize
    send bss
sendOutput conn send (OutStream s dats fin) = do
    sendStreamFragment conn send s dats fin
sendOutput conn send (OutPlainPacket (PlainPacket hdr0 plain0) pns) = do
    let lvl = packetEncryptionLevel hdr0
    let frames = filter retransmittable $ plainFrames plain0
    bss <- construct conn lvl frames pns $ Just maximumQUICPacketSize
    send bss

sendCryptoFragments :: Connection -> SendMany -> [(EncryptionLevel, CryptoData)] ->IO ()
sendCryptoFragments conn send = loop 1024 maximumQUICPacketSize id
  where
    loop _ _ pre0 [] =
        let bss0 = pre0 []
         in unless (null bss0) (send bss0)
    loop len0 sz0 pre0 ((lvl, bs) : xs)
        | B.length bs > len0 = do
            let (target, rest) = B.splitAt len0 bs
            frame1 <- cryptoFrame conn target lvl
            bss1 <- construct conn lvl [frame1] [] (Just sz0)
            send (pre0 bss1)
            loop 1024 maximumQUICPacketSize id ((lvl, rest) : xs)
        | otherwise = do
            frame1 <- cryptoFrame conn bs lvl
            let mTargetSize = if null xs then Just sz0 else Nothing
            bss1 <- construct conn lvl [frame1] [] mTargetSize
            let len1 = len0 - B.length bs
                sz1  = sz0  - sum (map B.length bss1)
            if sz1 >= 48
                then loop len1 sz1 (pre0 . (bss1 ++)) xs
                else do
                    bss1' <- construct conn lvl [frame1] [] (Just sz0)
                    send (pre0 bss1')
                    loop 1024 maximumQUICPacketSize id xs

----------------------------------------------------------------

threshold :: Int
threshold  =  832

limitation :: Int
limitation = 1040

totalLen :: [ByteString] -> Int
totalLen = sum . map B.length

packFin :: Connection -> Stream -> Bool -> IO Bool
packFin _    _ True  = return True
packFin conn s False = do
    mx <- tryPeekOutput conn
    case mx of
      Just (OutStream s1 [] True)
          | streamId s == streamId s1 -> do
                _ <- takeOutput conn
                return True
      _ -> return False

sendStreamFragment :: Connection -> SendMany -> Stream -> [ByteString] -> Bool -> IO ()
sendStreamFragment conn send s dats fin0 = do
    closed <- getStreamFin s
    let sid = streamId s
    if closed then
        connDebugLog conn $ "Stream " ++ show sid ++ " is already closed."
      else do
        fin <- packFin conn s fin0
        let len = totalLen dats
        if len < limitation then do
            off <- getStreamOffset s len
            let frame = StreamF sid off dats fin
            sendStreamSmall conn send frame len
          else
            sendStreamLarge conn send s dats fin
        when fin $ setStreamFin s

sendStreamSmall :: Connection -> SendMany -> Frame -> Int -> IO ()
sendStreamSmall conn send frame0 total0 = do
    ref <- newIORef []
    build <- loop ref (frame0 :) total0
    let frames = build []
    ready <- isConnection1RTTReady conn
    let lvl | ready     = RTT1Level
            | otherwise = RTT0Level
    bss <- construct conn lvl frames [] $ Just maximumQUICPacketSize
    send bss
    readIORef ref >>= mapM_ setStreamFin
  where
    tryPeekOutput' = do
        mx <- tryPeekOutput conn
        case mx of
          Nothing -> do
              yield
              tryPeekOutput conn
          Just _ -> return mx
    loop ref build total = do
        mx <- tryPeekOutput'
        case mx of
          Just (OutStream s dats fin0) -> do
              closed <- getStreamFin s
              let sid = streamId s
              if closed then do
                  connDebugLog conn $ "Stream " ++ show sid ++ " is already closed."
                  return build
                else do
                  let len = totalLen dats
                      total' = len + total
                  if total' < limitation then do
                      _ <- takeOutput conn
                      fin <- packFin conn s fin0 -- must be after takeOutput
                      off <- getStreamOffset s len
                      let frame = StreamF sid off dats fin
                          build' = build . (frame :)
                      when fin $ modifyIORef' ref (s :)
                      loop ref build' total'
                    else
                      return build
          _ -> return build

sendStreamLarge :: Connection -> SendMany -> Stream -> [ByteString] -> Bool -> IO ()
sendStreamLarge conn send s dats0 fin0 = loop fin0 dats0
  where
    sid = streamId s
    loop _ [] = return ()
    loop fin dats = do
        let (dats1,dats2) = splitChunks dats
            len = totalLen dats1
        off <- getStreamOffset s len
        let fin1 = fin && null dats2
            frame = StreamF sid off dats1 fin1
        ready <- isConnection1RTTReady conn
        let lvl | ready     = RTT1Level
                | otherwise = RTT0Level
        bss <- construct conn lvl [frame] [] $ Just maximumQUICPacketSize
        send bss
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
        siz = len + siz0
        len = B.length b

----------------------------------------------------------------

resender :: Connection -> IO ()
resender conn = handleIOLog cleanupAction logAction $ forever $ do
    threadDelay 100000
    ppktpns <- getRetransmissions conn (MilliSeconds 600)
    established <- isConnectionEstablished conn
    -- Some implementations do not return Ack for Initial and Handshake
    -- correctly. We should consider that the success of handshake
    -- implicitly acknowledge them.
    let ppktpns'
         | established = filter isRTTxLevel ppktpns
         | otherwise   = ppktpns
    mapM_ put ppktpns'
    ppns <- getPeerPacketNumbers conn RTT1Level
    when (ppns /= emptyPeerPacketNumbers) $ do
        -- generating ACK
        putOutput conn $ OutControl RTT1Level []
  where
    cleanupAction = putInput conn $ InpError ConnectionIsClosed
    logAction msg = connDebugLog conn ("resender: " ++ msg)
    put (ppkt,pns) = putOutput conn $ OutPlainPacket ppkt pns

isRTTxLevel :: (PlainPacket,[PacketNumber]) -> Bool
isRTTxLevel (PlainPacket hdr _,_) = lvl == RTT1Level || lvl == RTT0Level
  where
    lvl = packetEncryptionLevel hdr
