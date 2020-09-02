{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Packet.Frame (
    encodeFrames
  , encodeFramesWithPadding
  , decodeFrames
  ) where

import Network.Socket.Internal (zeroMemory)
import qualified Data.ByteString as B
import qualified Data.ByteString.Short as Short

import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Types

----------------------------------------------------------------

encodeFrames :: [Frame] -> IO ByteString
encodeFrames frames = withWriteBuffer 2048 $ \wbuf ->
  mapM_ (encodeFrame wbuf) frames

encodeFramesWithPadding :: Buffer -> BufferSize -> [Frame] -> IO (ByteString, Int)
encodeFramesWithPadding buf siz frames = do
    zeroMemory buf $ fromIntegral siz -- padding
    wbuf <- newWriteBuffer buf siz
    save wbuf
    mapM_ (encodeFrame wbuf) frames
    size <- savingSize wbuf
    goBack wbuf
    bs <- extractByteString wbuf siz
    return (bs, size)

encodeFrame :: WriteBuffer -> Frame -> IO ()
encodeFrame wbuf (Padding n) = replicateM_ n $ write8 wbuf 0x00
encodeFrame wbuf Ping = write8 wbuf 0x01
encodeFrame wbuf (Ack (AckInfo largest range1 ranges) (Milliseconds delay)) = do
    write8 wbuf 0x02
    encodeInt' wbuf largest
    encodeInt' wbuf $ fromIntegral delay
    encodeInt' wbuf $ fromIntegral $ length ranges
    encodeInt' wbuf $ fromIntegral range1
    mapM_ putRanges ranges
  where
    putRanges (gap,rng) = do
        encodeInt' wbuf $ fromIntegral gap
        encodeInt' wbuf $ fromIntegral rng
encodeFrame wbuf (CryptoF off cdata) = do
    write8 wbuf 0x06
    encodeInt' wbuf $ fromIntegral off
    encodeInt' wbuf $ fromIntegral $ B.length cdata
    copyByteString wbuf cdata
encodeFrame wbuf (NewToken token) = do
    write8 wbuf 0x07
    encodeInt' wbuf $ fromIntegral $ B.length token
    copyByteString wbuf token
encodeFrame wbuf (StreamF sid off dats fin) = do
    let flag0 = 0x08 .|. 0x02 -- len
        flag1 | off /= 0  = flag0 .|. 0x04 -- off
              | otherwise = flag0
        flag2 | fin       = flag1 .|. 0x01 -- fin
              | otherwise = flag1
    write8 wbuf flag2
    encodeInt' wbuf $ fromIntegral sid
    when (off /= 0) $ encodeInt' wbuf $ fromIntegral off
    encodeInt' wbuf $ fromIntegral $ sum $ map B.length dats
    mapM_ (copyByteString wbuf) dats
encodeFrame wbuf (MaxData n) = do
    write8 wbuf 0x10
    encodeInt' wbuf $ fromIntegral n
encodeFrame wbuf (MaxStreamData sid n) = do
    write8 wbuf 0x11
    encodeInt' wbuf $ fromIntegral sid
    encodeInt' wbuf $ fromIntegral n
encodeFrame wbuf (MaxStreams dir ms) = do
    case dir of
      Bidirectional  -> write8 wbuf 0x12
      Unidirectional -> write8 wbuf 0x13
    encodeInt' wbuf $ fromIntegral ms
encodeFrame wbuf (DataBlocked n) = do
    write8 wbuf 0x14
    encodeInt' wbuf $ fromIntegral n
encodeFrame wbuf (StreamDataBlocked sid n) = do
    write8 wbuf 0x15
    encodeInt' wbuf $ fromIntegral sid
    encodeInt' wbuf $ fromIntegral n
encodeFrame wbuf (StreamsBlocked dir ms) = do
    case dir of
      Bidirectional  -> write8 wbuf 0x16
      Unidirectional -> write8 wbuf 0x17
    encodeInt' wbuf $ fromIntegral ms
encodeFrame wbuf (NewConnectionID cidInfo rpt) = do
    write8 wbuf 0x18
    encodeInt' wbuf $ fromIntegral $ cidInfoSeq cidInfo
    encodeInt' wbuf $ fromIntegral rpt
    let (cid, len) = unpackCID $ cidInfoCID cidInfo
    write8 wbuf len
    copyShortByteString wbuf cid
    let StatelessResetToken token = cidInfoSRT cidInfo
    copyShortByteString wbuf token
encodeFrame wbuf (RetireConnectionID seqNum) = do
    write8 wbuf 0x19
    encodeInt' wbuf $ fromIntegral seqNum
encodeFrame wbuf (PathChallenge (PathData pdata)) = do
    write8 wbuf 0x1a
    copyByteString wbuf $ Short.fromShort pdata
encodeFrame wbuf (PathResponse (PathData pdata)) = do
    write8 wbuf 0x1b
    copyByteString wbuf $ Short.fromShort pdata
encodeFrame wbuf (ConnectionCloseQUIC err ftyp reason) = do
    write8 wbuf 0x1c
    encodeInt' wbuf $ fromIntegral $ fromTransportError err
    encodeInt' wbuf $ fromIntegral ftyp
    encodeInt' wbuf $ fromIntegral $ Short.length reason
    copyShortByteString wbuf reason
encodeFrame wbuf (ConnectionCloseApp (ApplicationError err) reason) = do
    write8 wbuf 0x1d
    encodeInt' wbuf $ fromIntegral err
    encodeInt' wbuf $ fromIntegral $ Short.length reason
    copyShortByteString wbuf reason
encodeFrame wbuf HandshakeDone =
    write8 wbuf 0x1e
encodeFrame _ _ = stdoutLogger "encodeFrame: not supported yet" -- fixme

----------------------------------------------------------------

decodeFrames :: ByteString -> IO [Frame]
decodeFrames bs = withReadBuffer bs $ loop id
  where
    loop frames rbuf = do
        ok <- (>= 1) <$> remainingSize rbuf
        if ok then do
            frame <- decodeFrame rbuf
            loop (frames . (frame:)) rbuf
          else
            return $ frames []

decodeFrame :: ReadBuffer -> IO Frame
decodeFrame rbuf = do
    ftyp <- fromIntegral <$> decodeInt' rbuf
    case ftyp :: FrameType of
      0x00 -> decodePaddingFrames rbuf
      0x01 -> return Ping
      0x02 -> decodeAckFrame rbuf
   -- 0x03 -> Ack with ECN Counts
      0x04 -> decodeResetStreamFrame rbuf
      0x05 -> decodeStopSending rbuf
      0x06 -> decodeCryptoFrame rbuf
      0x07 -> decodeNewToken rbuf
      x | 0x08 <= x && x <= 0x0f -> do
              let off = testBit x 2
                  len = testBit x 1
                  fin = testBit x 0
              decodeStreamFrame rbuf off len fin
      0x10 -> decodeMaxData rbuf
      0x11 -> decodeMaxStreamData rbuf
      0x12 -> decodeMaxStreams rbuf Bidirectional
      0x13 -> decodeMaxStreams rbuf Unidirectional
      0x14 -> decodeDataBlocked rbuf
      0x15 -> decodeStreamDataBlocked rbuf
      0x16 -> decodeStreamsBlocked rbuf Bidirectional
      0x17 -> decodeStreamsBlocked rbuf Unidirectional
      0x18 -> decodeNewConnectionID rbuf
      0x19 -> decodeRetireConnectionID rbuf
      0x1a -> decodePathChallenge rbuf
      0x1b -> decodePathResponse rbuf
      0x1c -> decodeConnectionCloseFrameQUIC rbuf
      0x1d -> decodeConnectionCloseFrameApp rbuf
      0x1e -> return HandshakeDone
      x    -> return $ UnknownFrame x

decodePaddingFrames :: ReadBuffer -> IO Frame
decodePaddingFrames rbuf = do
    room <- remainingSize rbuf
    loop 1 room
  where
    loop n 0 = return $ Padding n
    loop n room = do
        ftyp <- read8 rbuf
        if ftyp == 0x00 then
            loop (n + 1) (room - 1)
          else do
            ff rbuf (-1)
            return $ Padding n

decodeCryptoFrame :: ReadBuffer -> IO Frame
decodeCryptoFrame rbuf = do
    off <- fromIntegral <$> decodeInt' rbuf
    len <- fromIntegral <$> decodeInt' rbuf
    cdata <- extractByteString rbuf len
    return $ CryptoF off cdata

decodeAckFrame :: ReadBuffer -> IO Frame
decodeAckFrame rbuf = do
    largest <- decodeInt' rbuf
    delay   <- fromIntegral <$> decodeInt' rbuf
    count   <- fromIntegral <$> decodeInt' rbuf
    range1  <- fromIntegral <$> decodeInt' rbuf
    ranges  <- getRanges count id
    return $ Ack (AckInfo largest range1 ranges) $ Milliseconds delay
  where
    getRanges 0 build = return $ build []
    getRanges n build = do
        gap <- fromIntegral <$> decodeInt' rbuf
        rng <- fromIntegral <$> decodeInt' rbuf
        let n' = n - 1 :: Int
        getRanges n' (build . ((gap, rng) :))

decodeResetStreamFrame :: ReadBuffer -> IO Frame
decodeResetStreamFrame _ = return ResetStream -- fixme

decodeStopSending :: ReadBuffer -> IO Frame
decodeStopSending rbuf = do
    sID <- fromIntegral <$> decodeInt' rbuf
    err <- ApplicationError . fromIntegral <$> decodeInt' rbuf
    return $ StopSending sID err

decodeNewToken :: ReadBuffer -> IO Frame
decodeNewToken rbuf = do
    len <- fromIntegral <$> decodeInt' rbuf
    NewToken <$> extractByteString rbuf len

decodeStreamFrame :: ReadBuffer -> Bool -> Bool -> Bool -> IO Frame
decodeStreamFrame rbuf hasOff hasLen fin = do
    sID <- fromIntegral <$> decodeInt' rbuf
    off <- if hasOff then
             fromIntegral <$> decodeInt' rbuf
           else
             return 0
    dat <- if hasLen then do
             len <- fromIntegral <$> decodeInt' rbuf
             extractByteString rbuf len
           else do
             len <- remainingSize rbuf
             extractByteString rbuf len
    return $ StreamF sID off [dat] fin

----------------------------------------------------------------

decodeMaxData :: ReadBuffer -> IO Frame
decodeMaxData rbuf = MaxData . fromIntegral <$> decodeInt' rbuf

decodeMaxStreamData :: ReadBuffer -> IO Frame
decodeMaxStreamData rbuf = do
    sID <- fromIntegral <$> decodeInt' rbuf
    maxstrdata <- fromIntegral <$> decodeInt' rbuf
    return $ MaxStreamData sID maxstrdata

decodeMaxStreams :: ReadBuffer -> Direction -> IO Frame
decodeMaxStreams rbuf dir = MaxStreams dir . fromIntegral <$> decodeInt' rbuf

----------------------------------------------------------------

decodeDataBlocked :: ReadBuffer -> IO Frame
decodeDataBlocked rbuf = DataBlocked . fromIntegral <$> decodeInt' rbuf

decodeStreamDataBlocked :: ReadBuffer -> IO Frame
decodeStreamDataBlocked rbuf = do
    sID <- fromIntegral <$> decodeInt' rbuf
    msd <- fromIntegral <$> decodeInt' rbuf
    return $ StreamDataBlocked sID msd

decodeStreamsBlocked :: ReadBuffer -> Direction -> IO Frame
decodeStreamsBlocked rbuf dir = StreamsBlocked dir . fromIntegral <$> decodeInt' rbuf

----------------------------------------------------------------

decodeConnectionCloseFrameQUIC  :: ReadBuffer -> IO Frame
decodeConnectionCloseFrameQUIC rbuf = do
    err    <- toTransportError . fromIntegral <$> decodeInt' rbuf
    ftyp   <- fromIntegral <$> decodeInt' rbuf
    len    <- fromIntegral <$> decodeInt' rbuf
    reason <- extractShortByteString rbuf len
    return $ ConnectionCloseQUIC err ftyp reason

decodeConnectionCloseFrameApp  :: ReadBuffer -> IO Frame
decodeConnectionCloseFrameApp rbuf = do
    err    <- ApplicationError . fromIntegral <$> decodeInt' rbuf
    len    <- fromIntegral <$> decodeInt' rbuf
    reason <- extractShortByteString rbuf len
    return $ ConnectionCloseApp err reason

decodeNewConnectionID :: ReadBuffer -> IO Frame
decodeNewConnectionID rbuf = do
    seqNum <- fromIntegral <$> decodeInt' rbuf
    rpt <- fromIntegral <$> decodeInt' rbuf
    cidLen <- fromIntegral <$> read8 rbuf
    cID <- makeCID <$> extractShortByteString rbuf cidLen
    token <- StatelessResetToken <$> extractShortByteString rbuf 16
    return $ NewConnectionID (CIDInfo seqNum cID token) rpt

decodeRetireConnectionID :: ReadBuffer -> IO Frame
decodeRetireConnectionID rbuf = do
    seqNum <- fromIntegral <$> decodeInt' rbuf
    return $ RetireConnectionID seqNum

decodePathChallenge :: ReadBuffer -> IO Frame
decodePathChallenge rbuf =
    PathChallenge . PathData <$> extractShortByteString rbuf 8

decodePathResponse :: ReadBuffer -> IO Frame
decodePathResponse rbuf =
    PathResponse . PathData <$> extractShortByteString rbuf 8
