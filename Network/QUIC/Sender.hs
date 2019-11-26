{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Sender where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Data.ByteString as B

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Transport
import Network.QUIC.Types

----------------------------------------------------------------

cryptoFrame :: Connection -> PacketType -> CryptoData -> Token -> IO [Frame]
cryptoFrame conn pt crypto token = do
    let len = B.length crypto
    off <- modifyCryptoOffset conn pt len
    case pt of
      Initial   -> do
          paddingFrames <- makePaddingFrames conn len token off
          return (Crypto off crypto : paddingFrames)
      Handshake -> return [Crypto off crypto]
      Short     -> return [Crypto off crypto]
      _         -> error "cryptoFrame"

makePaddingFrames :: Connection -> Int -> Token -> Int -> IO [Frame]
makePaddingFrames conn len token off
  | isClient conn = do
        let (_, dcidlen) = unpackCID $ myCID conn
        (_, scidlen) <- unpackCID <$> getPeerCID conn
        let tokenLen = B.length token
        let extra = 1 + 4
                  + 1 + fromIntegral dcidlen
                  + 1 + fromIntegral scidlen
                  + (if tokenLen <= 63 then 1 else 2)
                  + tokenLen
                  + 2 -- length
                  + 2 -- packet number
                  -- frame
                  + 1
                  + (if off <= 63 then 1 else 2)
                  + 2
                  + defaultCipherOverhead
            padlen = 1200 - len - extra
        return $ replicate padlen Padding
makePaddingFrames _ _ _ _ = return []

----------------------------------------------------------------

construct :: Connection -> Segment -> PacketType -> [Frame] -> Token -> IO ByteString
construct conn seg pt frames token = do
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
        pns <- getPNs conn Initial
        if nullPNs pns then
            return Nothing
          else do
            -- This packet will not be acknowledged.
            clearPNs conn Initial
            mypn <- getPacketNumber conn
            let ackFrame = Ack (toAckInfo $ fromPNs pns) 0
                pkt = InitialPacket currentDraft peercid mycid "" mypn [ackFrame]
            Just <$> encodePacket conn pkt
    constructAckPacket Short peercid = do
        pns <- getPNs conn Handshake
        if nullPNs pns then
            return Nothing
          else do
            -- This packet will not be acknowledged.
            clearPNs conn Handshake
            mypn <- getPacketNumber conn
            let ackFrame = Ack (toAckInfo $ fromPNs pns) 0
                pkt = HandshakePacket currentDraft peercid mycid mypn [ackFrame]
            Just <$> encodePacket conn pkt
    constructAckPacket _ _ = return Nothing
    constructTargetPacket peercid = do
        mypn <- getPacketNumber conn
        pns <- getPNs conn pt
        let frames'
              | null pns  = frames
              | otherwise = Ack (toAckInfo $ fromPNs pns) 0 : frames
        let pkt = case pt of
              Initial   -> InitialPacket   currentDraft peercid mycid token mypn frames'
              Handshake -> HandshakePacket currentDraft peercid mycid       mypn frames'
              Short     -> ShortPacket                  peercid             mypn frames'
              _         -> error "construct"
        keepSegment conn mypn seg pt pns
        encodePacket conn pkt

----------------------------------------------------------------

sender :: Connection -> IO ()
sender conn = loop
  where
    loop = forever $ do
        seg <- atomically $ readTQueue $ outputQ conn
        case seg of
          H pt cdat token -> do
              frames <- cryptoFrame conn pt cdat token
              bs <- construct conn seg pt frames token
              connSend conn bs
          C pt frames -> do
              bs <- construct conn seg pt frames emptyToken
              connSend conn bs
          S sid dat -> do
              bs <- construct conn seg Short [Stream sid 0 dat True] emptyToken -- fixme: off
              connSend conn bs
          _ -> return ()

----------------------------------------------------------------

resender :: Connection -> IO ()
resender conn = forever $ do
    threadDelay 25000
    -- retransQ
    segs <- updateSegment conn (MilliSeconds 25)
    mapM_ (atomically . writeTQueue (outputQ conn)) segs
