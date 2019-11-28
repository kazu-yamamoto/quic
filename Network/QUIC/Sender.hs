{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Sender (
    sender
  , resender
  ) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Data.ByteString as B

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Transport
import Network.QUIC.Types

----------------------------------------------------------------

cryptoFrame :: Connection -> CryptoData -> EncryptionLevel -> IO Frame
cryptoFrame conn crypto lvl = do
    let len = B.length crypto
    off <- modifyCryptoOffset conn lvl len
    return $ Crypto off crypto

maximumQUICPacketSize :: Int
maximumQUICPacketSize = 1200

makePaddingFrames :: Connection -> Frame -> Token -> IO [Frame]
makePaddingFrames conn (Crypto off crypto) token
  | isClient conn = do
        let (_, dcidlen) = unpackCID $ myCID conn
        (_, scidlen) <- unpackCID <$> getPeerCID conn
        let len = B.length crypto
            tokenLen = B.length token
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
makePaddingFrames _ _ _ = return []

----------------------------------------------------------------

construct :: Connection -> Output -> EncryptionLevel -> [Frame] -> Token -> Bool -> IO ByteString
construct conn out lvl frames token genLowerAck = do
    peercid <- getPeerCID conn
    if genLowerAck then do
        mbin0 <- constructAckPacket lvl peercid
        case mbin0 of
          Nothing   -> constructTargetPacket peercid
          Just bin0 -> do
              bin1 <- constructTargetPacket peercid
              return $ bin0 `B.append` bin1
      else
        constructTargetPacket peercid
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
        keepOutput conn mypn out lvl pns
        encodePacket conn pkt

----------------------------------------------------------------

sender :: Connection -> IO ()
sender conn = loop
  where
    loop = forever $ do
        out <- atomically $ readTQueue $ outputQ conn
        case out of
          OutHndClientHello0 ch _mEarydata -> do
              frame <- cryptoFrame conn ch InitialLevel
              paddingFrames <- makePaddingFrames conn frame emptyToken
              let frames = frame : paddingFrames
              bs <- construct conn out InitialLevel frames emptyToken False
              connSend conn bs
          OutHndClientHelloR ch _mEarydata token -> do
              frame <- cryptoFrame conn ch InitialLevel
              paddingFrames <- makePaddingFrames conn frame token
              let frames = frame : paddingFrames
              bs <- construct conn out InitialLevel frames token False
              connSend conn bs
          OutHndServerHello  sh sf -> do
              frame0 <- cryptoFrame conn sh InitialLevel
              bs0 <- construct conn out InitialLevel [frame0] emptyToken False
              frame1 <- cryptoFrame conn sf HandshakeLevel
              bs1 <- construct conn out HandshakeLevel [frame1] emptyToken False
              connSend conn (bs0 `B.append` bs1)
          OutHndServerHelloR sh -> do
              frame <- cryptoFrame conn sh InitialLevel
              bs <- construct conn out InitialLevel [frame] emptyToken False
              connSend conn bs
          OutHndClientFinished cf -> do
              frame <- cryptoFrame conn cf HandshakeLevel
              bs <- construct conn out HandshakeLevel [frame] emptyToken True
              connSend conn bs
          OutHndServerNST nst -> do
              frame <- cryptoFrame conn nst RTT1Level
              bs <- construct conn out RTT1Level [frame] emptyToken True
              connSend conn bs
          OutControl lvl frames -> do
              bs <- construct conn out lvl frames emptyToken False
              connSend conn bs
          OutStream sid dat -> do
              bs <- construct conn out RTT1Level [Stream sid 0 dat True] emptyToken False -- fixme: off
              connSend conn bs

----------------------------------------------------------------

resender :: Connection -> IO ()
resender conn = forever $ do
    threadDelay 25000
    -- retransQ
    outs <- updateOutput conn (MilliSeconds 25)
    mapM_ (atomically . writeTQueue (outputQ conn)) outs
