{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Sender where

import Control.Concurrent.STM
import qualified Data.ByteString as B

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Transport

-- |
-- >>> constructAckFrame [9]
-- Ack 9 0 0 []
-- >>> constructAckFrame [9,8,7]
-- Ack 9 0 2 []
-- >>> constructAckFrame [8,7,3,2]
-- Ack 8 0 1 [(2,1)]
-- >>> constructAckFrame [9,8,7,5,4]
-- Ack 9 0 2 [(0,1)]
constructAckFrame :: [PacketNumber] -> Frame
constructAckFrame []  = error "constructAckFrame"
constructAckFrame [l] = Ack l 0 0 []
constructAckFrame (l:ls)  = ack l ls 0
  where
    ack _ []     fr = Ack l 0 fr []
    ack p (x:xs) fr
      | p - 1 == x  = ack x xs (fr+1)
      | otherwise   = Ack l 0 fr $ ranges x xs (fromIntegral (p - x) - 2) 0
    ranges _ [] g r = [(g, r)]
    ranges p (x:xs) g r
      | p - 1 == x  = ranges x xs g (r+1)
      | otherwise   = (g, r) : ranges x xs (fromIntegral(p - x) - 2) 0

----------------------------------------------------------------

cryptoFrame :: Connection -> PacketType -> CryptoData -> IO [Frame]
cryptoFrame conn pt crypto = do
    let len = B.length crypto
    off <- modifyCryptoOffset conn pt len
    case pt of
      Initial   -> return (Crypto off crypto : replicate 963 Padding)
      Handshake -> return [Crypto off crypto]
      Short     -> return [Crypto off crypto]
      _         -> error "cryptoFrame"

----------------------------------------------------------------

construct :: Connection -> PacketType -> [Frame] -> IO ByteString
construct conn pt frames = do
    peercid <- getPeerCID conn
    mbin0 <- constructAckPacket pt peercid
    case mbin0 of
      Nothing   -> constructTargetPacket peercid
      Just bin0 -> do
          bin1 <- constructTargetPacket peercid
          return $ bin0 `B.append` bin1
  where
    mycid = myCID conn
    constructAckPacket Handshake peercid = do
        pns <- clearPNs conn Initial
        if null pns then
            return Nothing
          else do
            mypn <- getPacketNumber conn
            let ackFrame = constructAckFrame pns
                pkt = InitialPacket currentDraft peercid mycid "" mypn [ackFrame]
            Just <$> encodePacket conn pkt
    constructAckPacket Short peercid = do
        pns <- clearPNs conn Handshake
        if null pns then
            return Nothing
          else do
            mypn <- getPacketNumber conn
            let ackFrame = constructAckFrame pns
                pkt = HandshakePacket currentDraft peercid mycid mypn [ackFrame]
            Just <$> encodePacket conn pkt
    constructAckPacket _ _ = return Nothing
    constructTargetPacket peercid = do
        mypn <- getPacketNumber conn
        pns <- clearPNs conn pt
        let frames'
              | null pns  = frames
              | otherwise = constructAckFrame pns : frames
        let pkt = case pt of
              Initial   -> InitialPacket   currentDraft peercid mycid "" mypn frames'
              Handshake -> HandshakePacket currentDraft peercid mycid    mypn frames'
              Short     -> ShortPacket                  peercid          mypn frames'
              _         -> error "construct"
        encodePacket conn pkt

----------------------------------------------------------------

sender :: Connection -> IO ()
sender conn = loop
  where
    loop = forever $ do
        seg <- atomically $ readTQueue $ outputQ conn
        case seg of
          H pt cdat -> do
              frames <- cryptoFrame conn pt cdat
              bs <- construct conn pt frames
              connSend conn bs
          C pt frames -> do
              bs <- construct conn pt frames
              connSend conn bs
          S sid dat -> do
              bs <- construct conn Short [Stream sid 0 dat True] -- fixme: off
              connSend conn bs
          _ -> return ()
