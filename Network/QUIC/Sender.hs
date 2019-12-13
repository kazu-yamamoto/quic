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
import Network.QUIC.Types

----------------------------------------------------------------

cryptoFrame :: Connection -> CryptoData -> EncryptionLevel -> IO Frame
cryptoFrame conn crypto lvl = do
    let len = B.length crypto
    off <- modifyCryptoOffset conn lvl len
    return $ Crypto off crypto

----------------------------------------------------------------

construct :: Connection -> Output -> EncryptionLevel -> [Frame] -> Bool -> Maybe Int -> IO [ByteString]
construct conn out lvl frames genLowerAck mTargetSize = do
    token <- getToken conn
    peercid <- getPeerCID conn
    if genLowerAck then do
        bss0 <- constructAckPacket lvl peercid token
        let total = sum (map B.length bss0)
            mTargetSize' = subtract total <$> mTargetSize
        bss1 <- constructTargetPacket peercid mTargetSize' token
        return (bss0 ++ bss1)
      else
        constructTargetPacket peercid mTargetSize token
  where
    mycid = myCID conn
    constructAckPacket HandshakeLevel peercid token = do
        pns <- getPNs conn InitialLevel
        if nullPNs pns then
            return []
          else do
            -- This packet will not be acknowledged.
            clearPNs conn InitialLevel
            mypn <- getPacketNumber conn
            let header   = Initial currentDraft peercid mycid token
                ackFrame = Ack (toAckInfo $ fromPNs pns) 0
                plain    = Plain (Flags 0) mypn [ackFrame]
                ppkt     = PlainPacket header plain
            encodePlainPacket conn ppkt Nothing
    constructAckPacket RTT1Level peercid _ = do
        pns <- getPNs conn HandshakeLevel
        if nullPNs pns then
            return []
          else do
            -- This packet will not be acknowledged.
            clearPNs conn HandshakeLevel
            mypn <- getPacketNumber conn
            let header   = Handshake currentDraft peercid mycid
                ackFrame = Ack (toAckInfo $ fromPNs pns) 0
                plain    = Plain (Flags 0) mypn [ackFrame]
                ppkt     = PlainPacket header plain
            encodePlainPacket conn ppkt Nothing
    constructAckPacket _ _ _ = return []
    constructTargetPacket peercid mlen token = do
        mypn <- getPacketNumber conn
        pns <- getPNs conn lvl
        let frames'
              | null pns  = frames
              | otherwise = Ack (toAckInfo $ fromPNs pns) 0 : frames
        let ppkt = case lvl of
              InitialLevel   -> PlainPacket (Initial   currentDraft peercid mycid token) (Plain (Flags 0) mypn frames')
              HandshakeLevel -> PlainPacket (Handshake currentDraft peercid mycid)       (Plain (Flags 0) mypn frames')
              RTT1Level      -> PlainPacket (Short                  peercid)             (Plain (Flags 0) mypn frames')
              _         -> error "construct"
        when (frames /= []) $ keepOutput conn mypn out lvl pns
        encodePlainPacket conn ppkt mlen

----------------------------------------------------------------

sender :: Connection -> IO ()
sender conn = loop
  where
    loop = forever $ do
        out <- atomically $ readTQueue $ outputQ conn
        case out of
          OutHndClientHello ch _mEarydata -> do
              frame <- cryptoFrame conn ch InitialLevel
              let frames = [frame]
              bss <- construct conn out InitialLevel frames False $ Just maximumQUICPacketSize
              connSend conn bss
          OutHndServerHello  sh sf -> do
              frame0 <- cryptoFrame conn sh InitialLevel
              bss0 <- construct conn out InitialLevel [frame0] False Nothing
              -- 824 = 1024 - 200 (size of sh)
              -- but 900 is good enough...
              let (sf1,sf2) = B.splitAt 824 sf
              if sf2 == "" then do
                  let size = maximumQUICPacketSize - sum (map B.length bss0)
                  frame1 <- cryptoFrame conn sf1 HandshakeLevel
                  bss1 <- construct conn out HandshakeLevel [frame1] False $ Just size
                  connSend conn (bss0 ++ bss1)
                else do
                  let size = maximumQUICPacketSize - sum (map B.length bss0)
                  frame1 <- cryptoFrame conn sf1 HandshakeLevel
                  bss1 <- construct conn out HandshakeLevel [frame1] False $ Just size
                  frame2 <- cryptoFrame conn sf2 HandshakeLevel
                  bss2 <- construct conn out HandshakeLevel [frame2] False $ Just maximumQUICPacketSize
                  connSend conn (bss0 ++ bss1)
                  connSend conn bss2
          OutHndServerHelloR sh -> do
              frame <- cryptoFrame conn sh InitialLevel
              bss <- construct conn out InitialLevel [frame] False $ Just maximumQUICPacketSize
              connSend conn bss
          OutHndClientFinished cf -> do
              -- fixme size
              frame <- cryptoFrame conn cf HandshakeLevel
              bss <- construct conn out HandshakeLevel [frame] True $ Just maximumQUICPacketSize
              connSend conn bss
          OutHndServerNST nst -> do
              frame <- cryptoFrame conn nst RTT1Level
              bss <- construct conn out RTT1Level [frame] True $ Just maximumQUICPacketSize
              connSend conn bss
          OutControl lvl frames -> do
              bss <- construct conn out lvl frames False $ Just maximumQUICPacketSize
              connSend conn bss
          OutStream sid dat -> do
              bss <- construct conn out RTT1Level [Stream sid 0 dat True] False $ Just maximumQUICPacketSize -- fixme: off
              connSend conn bss

----------------------------------------------------------------

resender :: Connection -> IO ()
resender conn = forever $ do
    threadDelay 25000
    outs <- getRetransmissions conn (MilliSeconds 25)
    open <- isConnectionOpen conn
    -- Some implementations do not return Ack for Initial and Handshake
    -- correctly. We should consider that the success of handshake
    -- implicitly acknowledge them.
    let outs'
         | open      = filter isEstablished outs
         | otherwise = outs
    mapM_ (atomically . writeTQueue (outputQ conn)) outs'

isEstablished :: Output -> Bool
isEstablished OutStream{}       = True
isEstablished OutControl{}      = True
isEstablished OutHndServerNST{} = True
isEstablished _                 = False
