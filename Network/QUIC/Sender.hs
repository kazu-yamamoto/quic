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

cryptoFrame :: Connection -> EncryptionLevel -> CryptoData -> Token -> IO [Frame]
cryptoFrame conn lvl crypto token = do
    let len = B.length crypto
    off <- modifyCryptoOffset conn lvl len
    case lvl of
      InitialLevel   -> do
          paddingFrames <- makePaddingFrames conn len token off
          return (Crypto off crypto : paddingFrames)
      RTT0Level      -> error "cryptoFrame"
      HandshakeLevel -> return [Crypto off crypto]
      RTT1Level      -> return [Crypto off crypto]

maximumQUICPacketSize :: Int
maximumQUICPacketSize = 1200

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
                  + (if len <= 63 then 1 else 2)
                  + 2 -- packet number
                  -- frame
                  + 1
                  + (if off <= 63 then 1 else 2)
                  + 2
                  + defaultCipherOverhead
            padlen = maximumQUICPacketSize - len - extra
        return $ replicate padlen Padding
makePaddingFrames _ _ _ _ = return []

----------------------------------------------------------------

construct :: Connection -> Segment -> EncryptionLevel -> [Frame] -> Token -> IO ByteString
construct conn seg lvl frames token = do
    peercid <- getPeerCID conn
    mbin0 <- constructAckPacket lvl peercid
    case mbin0 of
      Nothing   -> constructTargetPacket peercid
      Just bin0 -> do
          bin1 <- constructTargetPacket peercid
          return $ bin0 `B.append` bin1
  where
    mycid = myCID conn
    constructAckPacket HandshakeLevel peercid = do
        pns <- getPNs conn InitialLevel
        if nullPNs pns then
            return Nothing
          else do
            -- This packet will not be acknowledged.
            clearPNs conn InitialLevel
            mypn <- getPacketNumber conn
            let ackFrame = Ack (toAckInfo $ fromPNs pns) 0
                pkt = InitialPacket currentDraft peercid mycid "" mypn [ackFrame]
            Just <$> encodePacket conn pkt
    constructAckPacket RTT1Level peercid = do
        pns <- getPNs conn HandshakeLevel
        if nullPNs pns then
            return Nothing
          else do
            -- This packet will not be acknowledged.
            clearPNs conn HandshakeLevel
            mypn <- getPacketNumber conn
            let ackFrame = Ack (toAckInfo $ fromPNs pns) 0
                pkt = HandshakePacket currentDraft peercid mycid mypn [ackFrame]
            Just <$> encodePacket conn pkt
    constructAckPacket _ _ = return Nothing
    constructTargetPacket peercid = do
        mypn <- getPacketNumber conn
        pns <- getPNs conn lvl
        let frames'
              | null pns  = frames
              | otherwise = Ack (toAckInfo $ fromPNs pns) 0 : frames
        let pkt = case lvl of
              InitialLevel   -> InitialPacket   currentDraft peercid mycid token mypn frames'
              HandshakeLevel -> HandshakePacket currentDraft peercid mycid       mypn frames'
              RTT1Level      -> ShortPacket                  peercid             mypn frames'
              _         -> error "construct"
        keepSegment conn mypn seg lvl pns
        encodePacket conn pkt

----------------------------------------------------------------

sender :: Connection -> IO ()
sender conn = loop
  where
    loop = forever $ do
        seg <- atomically $ readTQueue $ outputQ conn
        case seg of
          H lvl cdat token -> do
              frames <- cryptoFrame conn lvl cdat token
              bs <- construct conn seg lvl frames token
              connSend conn bs
          C lvl frames -> do
              bs <- construct conn seg lvl frames emptyToken
              connSend conn bs
          S sid dat -> do
              bs <- construct conn seg RTT1Level [Stream sid 0 dat True] emptyToken -- fixme: off
              connSend conn bs
          _ -> return ()

----------------------------------------------------------------

resender :: Connection -> IO ()
resender conn = forever $ do
    threadDelay 25000
    -- retransQ
    segs <- updateSegment conn (MilliSeconds 25)
    mapM_ (atomically . writeTQueue (outputQ conn)) segs
