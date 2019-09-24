module Network.QUIC.Transport.Frame where

import qualified Data.ByteString as B

import Network.QUIC.Imports
import Network.QUIC.Transport.Types
import Network.QUIC.Transport.Integer

----------------------------------------------------------------

encodeFrames :: [Frame] -> IO ByteString
encodeFrames frames = withWriteBuffer 2048 $ \wbuf ->
  mapM_ (encodeFrame wbuf) frames

encodeFrame :: WriteBuffer -> Frame -> IO ()
encodeFrame wbuf Padding = write8 wbuf 0x00
encodeFrame wbuf Ping = write8 wbuf 0x01
encodeFrame wbuf (Crypto off cdata) = do
    write8 wbuf 0x06
    encodeInt' wbuf $ fromIntegral off
    encodeInt' wbuf $ fromIntegral $ B.length cdata
    copyByteString wbuf cdata
encodeFrame wbuf (Ack largest delay range1 ranges) = do
    write8 wbuf 0x02
    encodeInt' wbuf largest
    encodeInt' wbuf $ fromIntegral delay
    encodeInt' wbuf $ fromIntegral $ length ranges
    encodeInt' wbuf $ fromIntegral $ range1
    -- fixme: ranges
encodeFrame _wbuf (Stream _sid _off _dat _fin) = undefined
encodeFrame _wbuf (ConnectionClose _ _) = undefined

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
    b0 <- read8 rbuf
    case b0 of
      0x00 -> return Padding
      0x01 -> return Ping
      0x02 -> decodeAckFrame rbuf
      0x06 -> decodeCryptoFrame rbuf
      x | 0x08 <= x && x <= 0x0f -> decodeStreamFrame rbuf
      0x1c -> decodeConnectionCloseFrame rbuf
      _x   -> error $ show _x

decodeCryptoFrame :: ReadBuffer -> IO Frame
decodeCryptoFrame rbuf = do
    off <- fromIntegral <$> decodeInt' rbuf
    len <- fromIntegral <$> decodeInt' rbuf
    cdata <- extractByteString rbuf len
    return $ Crypto off cdata

decodeAckFrame :: ReadBuffer -> IO Frame
decodeAckFrame rbuf = do
    largest <- decodeInt' rbuf
    delay   <- fromIntegral <$> decodeInt' rbuf
    _count  <- (fromIntegral <$> decodeInt' rbuf) :: IO Int
    range1  <- fromIntegral <$> decodeInt' rbuf
    -- fixme: ranges
    return $ Ack largest delay range1 []

decodeStreamFrame :: ReadBuffer -> IO Frame
decodeStreamFrame = undefined

decodeConnectionCloseFrame  :: ReadBuffer -> IO Frame
decodeConnectionCloseFrame rbuf = do
    errcode <- fromIntegral <$> decodeInt' rbuf
    len <- fromIntegral <$> decodeInt' rbuf
    reason <- extractByteString rbuf len
    return $ ConnectionClose errcode reason
