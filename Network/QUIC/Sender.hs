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
import Network.QUIC.Packet
import Network.QUIC.TLS
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
        return $ [Padding padlen]
makePaddingFrames _ _ _ = return []

----------------------------------------------------------------

construct :: Connection -> Output -> EncryptionLevel -> [Frame] -> Token -> Bool -> IO [ByteString]
construct conn out lvl frames token genLowerAck = do
    peercid <- getPeerCID conn
    if genLowerAck then do
        bss0 <- constructAckPacket lvl peercid
        bss1 <- constructTargetPacket peercid
        return (bss0 ++ bss1)
      else
        constructTargetPacket peercid
  where
    mycid = myCID conn
    constructAckPacket HandshakeLevel peercid = do
        pns <- getPNs conn InitialLevel
        if nullPNs pns then
            return []
          else do
            -- This packet will not be acknowledged.
            clearPNs conn InitialLevel
            mypn <- getPacketNumber conn
            let header   = Initial currentDraft peercid mycid ""
                ackFrame = Ack (toAckInfo $ fromPNs pns) 0
                plain    = Plain 0 mypn [ackFrame]
                ppkt     = PlainPacket header plain
            encodePlainPacket conn ppkt
    constructAckPacket RTT1Level peercid = do
        pns <- getPNs conn HandshakeLevel
        if nullPNs pns then
            return []
          else do
            -- This packet will not be acknowledged.
            clearPNs conn HandshakeLevel
            mypn <- getPacketNumber conn
            let header   = Handshake currentDraft peercid mycid
                ackFrame = Ack (toAckInfo $ fromPNs pns) 0
                plain    = Plain 0 mypn [ackFrame]
                ppkt     = PlainPacket header plain
            encodePlainPacket conn ppkt
    constructAckPacket _ _ = return []
    constructTargetPacket peercid = do
        mypn <- getPacketNumber conn
        pns <- getPNs conn lvl
        let frames'
              | null pns  = frames
              | otherwise = Ack (toAckInfo $ fromPNs pns) 0 : frames
        let ppkt = case lvl of
              InitialLevel   -> PlainPacket (Initial   currentDraft peercid mycid token) (Plain 0 mypn frames')
              HandshakeLevel -> PlainPacket (Handshake currentDraft peercid mycid)       (Plain 0 mypn frames')
              RTT1Level      -> PlainPacket (Short                  peercid)             (Plain 0 mypn frames')
              _         -> error "construct"
        keepOutput conn mypn out lvl pns
        encodePlainPacket conn ppkt

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
              bss <- construct conn out InitialLevel frames emptyToken False
              connSend conn bss
          OutHndClientHelloR ch _mEarydata token -> do
              let frame = Crypto 0 ch
              paddingFrames <- makePaddingFrames conn frame token
              let frames = frame : paddingFrames
              bss <- construct conn out InitialLevel frames token False
              connSend conn bss
          OutHndServerHello  sh sf -> do
              frame0 <- cryptoFrame conn sh InitialLevel
              bss0 <- construct conn out InitialLevel [frame0] emptyToken False
              frame1 <- cryptoFrame conn sf HandshakeLevel
              bss1 <- construct conn out HandshakeLevel [frame1] emptyToken False
              connSend conn (bss0 ++ bss1)
          OutHndServerHelloR sh -> do
              frame <- cryptoFrame conn sh InitialLevel
              bss <- construct conn out InitialLevel [frame] emptyToken False
              connSend conn bss
          OutHndClientFinished cf -> do
              frame <- cryptoFrame conn cf HandshakeLevel
              bss <- construct conn out HandshakeLevel [frame] emptyToken True
              connSend conn bss
          OutHndServerNST nst -> do
              frame <- cryptoFrame conn nst RTT1Level
              bss <- construct conn out RTT1Level [frame] emptyToken True
              connSend conn bss
          OutControl lvl frames -> do
              bss <- construct conn out lvl frames emptyToken False
              connSend conn bss
          OutStream sid dat -> do
              bss <- construct conn out RTT1Level [Stream sid 0 dat True] emptyToken False -- fixme: off
              connSend conn bss

----------------------------------------------------------------

resender :: Connection -> IO ()
resender conn = forever $ do
    threadDelay 25000
    -- retransQ
    outs <- updateOutput conn (MilliSeconds 25)
    mapM_ (atomically . writeTQueue (outputQ conn)) outs
