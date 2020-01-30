{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Sender (
    sender
  , resender
  ) where

import Control.Concurrent
import qualified Data.ByteString as B

import Network.QUIC.Connection
import Network.QUIC.Exception
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

construct :: Connection -> Output -> [PacketNumber] -> EncryptionLevel -> [Frame] -> Bool -> Maybe Int -> IO [ByteString]
construct conn out pns lvl frames genLowerAck mTargetSize = do
    ver <- getVersion conn
    token <- getToken conn
    peercid <- getPeerCID conn
    if genLowerAck then do
        bss0 <- constructAckPacket lvl ver peercid token
        let total = sum (map B.length bss0)
            mTargetSize' = subtract total <$> mTargetSize
        bss1 <- constructTargetPacket ver peercid mTargetSize' token
        return (bss0 ++ bss1)
      else
        constructTargetPacket ver peercid mTargetSize token
  where
    mycid = myCID conn
    constructAckPacket HandshakeLevel ver peercid token = do
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
            encodePlainPacket conn ppkt Nothing
    constructAckPacket RTT1Level ver peercid _ = do
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
            encodePlainPacket conn ppkt Nothing
    constructAckPacket _ _ _ _ = return []
    constructTargetPacket ver peercid mlen token = do
        mypn <- getPacketNumber conn
        ppns <- getPeerPacketNumbers conn lvl
        let frames'
              | nullPeerPacketNumbers ppns = frames
              | otherwise   = Ack (toAckInfo $ fromPeerPacketNumbers ppns) 0 : frames
        let ppkt = case lvl of
              InitialLevel   -> PlainPacket (Initial   ver peercid mycid token) (Plain (Flags 0) mypn frames')
              RTT0Level      -> PlainPacket (RTT0      ver peercid mycid)       (Plain (Flags 0) mypn frames')
              HandshakeLevel -> PlainPacket (Handshake ver peercid mycid)       (Plain (Flags 0) mypn frames')
              RTT1Level      -> PlainPacket (Short         peercid)             (Plain (Flags 0) mypn frames')
        -- fixme: how to receive AKC for 0-RTT?
        when (frames /= [] && lvl /= RTT0Level) $
            keepOutput conn (mypn:pns) out lvl ppns
        encodePlainPacket conn ppkt mlen

----------------------------------------------------------------

sender :: Connection -> IO ()
sender conn = handle (handlerIO conn) $ forever $ do
    (out,pns) <- takeOutput conn
    case out of
      OutHndClientHello ch mEarlyData -> do
          frame <- cryptoFrame conn ch InitialLevel
          let frames = [frame]
          -- fixme: the case where mEarlyData is larger.
          case mEarlyData of
            Nothing -> do
                bss <- construct conn out pns InitialLevel frames False $ Just maximumQUICPacketSize
                connSend conn bss
            Just (sid,earlyData) -> do
                let out0 = OutHndClientHello ch Nothing
                bss0 <- construct conn out0 pns InitialLevel frames False Nothing
                let size = maximumQUICPacketSize - sum (map B.length bss0)
                off <- modifyStreamOffset conn sid $ B.length earlyData
                let out1 = OutStream sid earlyData off True
                bss1 <- construct conn out1 pns RTT0Level [Stream sid off earlyData True] False $ Just size
                connSend conn (bss0 ++ bss1)
      OutHndServerHello  sh sf -> do
          frame0 <- cryptoFrame conn sh InitialLevel
          bss0 <- construct conn out pns InitialLevel [frame0] False Nothing
          -- 824 = 1024 - 200 (size of sh)
          -- but 900 is good enough...
          let (sf1,sf2) = B.splitAt 824 sf
          let size = maximumQUICPacketSize - sum (map B.length bss0)
          frame1 <- cryptoFrame conn sf1 HandshakeLevel
          bss1 <- construct conn out pns HandshakeLevel [frame1] False $ Just size
          connSend conn (bss0 ++ bss1)
          let sendRest rsf0 = do
                let (rsf,rest) = B.splitAt 1024 rsf0
                rframe <- cryptoFrame conn rsf HandshakeLevel
                rbss <- construct conn out pns HandshakeLevel [rframe] False $ Just maximumQUICPacketSize
                connSend conn rbss
                when (rest /= "") $ sendRest rest
          sendRest sf2
      OutHndServerHelloR sh -> do
          frame <- cryptoFrame conn sh InitialLevel
          bss <- construct conn out pns InitialLevel [frame] False $ Just maximumQUICPacketSize
          connSend conn bss
      OutHndClientFinished cf -> do
          -- fixme size
          frame <- cryptoFrame conn cf HandshakeLevel
          bss <- construct conn out pns HandshakeLevel [frame] True $ Just maximumQUICPacketSize
          connSend conn bss
      OutHndServerNST nst -> do
          frame <- cryptoFrame conn nst RTT1Level
          bss <- construct conn out pns RTT1Level [frame] True $ Just maximumQUICPacketSize
          connSend conn bss
      OutControl lvl frames -> do
          bss <- construct conn out pns lvl frames False $ Just maximumQUICPacketSize
          connSend conn bss
      OutStream sid dat off fin -> do
          bss <- construct conn out pns RTT1Level [Stream sid off dat fin] False $ Just maximumQUICPacketSize
          connSend conn bss

----------------------------------------------------------------

resender :: Connection -> IO ()
resender conn = handle (handlerIO conn) $ forever $ do
    threadDelay 100000
    outpns <- getRetransmissions conn (MilliSeconds 250)
    open <- isConnectionOpen conn
    -- Some implementations do not return Ack for Initial and Handshake
    -- correctly. We should consider that the success of handshake
    -- implicitly acknowledge them.
    let outpns'
         | open      = filter isEstablished outpns
         | otherwise = outpns
    mapM_ (putOutput' conn) outpns'

isEstablished :: (Output,[PacketNumber]) -> Bool
isEstablished (OutStream{},_)       = True
isEstablished (OutControl{},_)      = True
isEstablished (OutHndServerNST{},_) = True
isEstablished _                     = False
