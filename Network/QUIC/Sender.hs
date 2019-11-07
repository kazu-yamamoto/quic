{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Sender where

import Control.Concurrent.STM
import qualified Data.ByteString as B

import Network.QUIC.Context
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

cryptoFrame :: Context -> PacketType -> CryptoData -> IO [Frame]
cryptoFrame ctx pt crypto = do
    let len = B.length crypto
    off <- modifyCryptoOffset ctx pt len
    case pt of
      Initial   -> return (Crypto off crypto : replicate 963 Padding)
      Handshake -> return [Crypto off crypto]
      Short     -> return [Crypto off crypto]
      _         -> error "cryptoFrame"

----------------------------------------------------------------

construct :: Context -> PacketType -> [Frame] -> IO ByteString
construct ctx pt frames = do
    peercid <- getPeerCID ctx
    mbin0 <- constructAckPacket pt peercid
    case mbin0 of
      Nothing   -> constructTargetPacket peercid
      Just bin0 -> do
          bin1 <- constructTargetPacket peercid
          return $ bin0 `B.append` bin1
  where
    mycid = myCID ctx
    constructAckPacket Handshake peercid = do
        pns <- clearPNs ctx Initial
        if null pns then
            return Nothing
          else do
            mypn <- getPacketNumber ctx
            let ackFrame = constructAckFrame pns
                pkt = InitialPacket Draft23 peercid mycid "" mypn [ackFrame]
            Just <$> encodePacket ctx pkt
    constructAckPacket Short peercid = do
        pns <- clearPNs ctx Handshake
        if null pns then
            return Nothing
          else do
            mypn <- getPacketNumber ctx
            let ackFrame = constructAckFrame pns
                pkt = HandshakePacket Draft23 peercid mycid mypn [ackFrame]
            Just <$> encodePacket ctx pkt
    constructAckPacket _ _ = return Nothing
    constructTargetPacket peercid = do
        mypn <- getPacketNumber ctx
        pns <- clearPNs ctx pt
        let frames'
              | pns == [] = frames
              | otherwise = constructAckFrame pns : frames
        let pkt = case pt of
              Initial   -> InitialPacket   Draft23 peercid mycid "" mypn frames'
              Handshake -> HandshakePacket Draft23 peercid mycid    mypn frames'
              Short     -> ShortPacket             peercid          mypn frames'
              _         -> error "construct"
        encodePacket ctx pkt

----------------------------------------------------------------

sender :: Context -> IO ()
sender ctx = loop
  where
    loop = forever $ do
        seg <- atomically $ readTQueue $ outputQ ctx
        case seg of
          H pt cdat -> do
              frames <- cryptoFrame ctx pt cdat
              bs <- construct ctx pt frames
              ctxSend ctx bs
          S sid dat -> do
              bs <- construct ctx Short [Stream sid 0 dat True] -- fixme: off
              ctxSend ctx bs
