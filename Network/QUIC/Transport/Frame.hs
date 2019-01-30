module Network.QUIC.Transport.Frame where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Network.ByteOrder

import Network.QUIC.Transport.Types
import Network.QUIC.Transport.Integer

----------------------------------------------------------------

encodeFrames :: [Frame] -> IO ByteString
encodeFrames frames = withWriteBuffer 2048 $ \wbuf ->
  mapM_ (encodeFrame wbuf) frames

encodeFrame :: WriteBuffer -> Frame -> IO ()
encodeFrame wbuf Padding = write8 wbuf 0x00
encodeFrame wbuf (Crypto off cdata) = do
    write8 wbuf 0x06
    encodeInt' wbuf $ fromIntegral off
    encodeInt' wbuf $ fromIntegral $ B.length cdata
    copyByteString wbuf cdata
encodeFrame wbuf (Ack la ad arc far) = do
    write8 wbuf 0x02
    encodeInt' wbuf la
    encodeInt' wbuf ad
    encodeInt' wbuf arc
    encodeInt' wbuf far

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
      0x02 -> decodeAckFrame rbuf
      0x06 -> decodeCryptoFrame rbuf
      _x   -> error $ show _x

decodeCryptoFrame :: ReadBuffer -> IO Frame
decodeCryptoFrame rbuf = do
    off <- fromIntegral <$> decodeInt' rbuf
    len <- fromIntegral <$> decodeInt' rbuf
    cdata <- extractByteString rbuf len
    return $ Crypto off cdata

-- fixme
decodeAckFrame :: ReadBuffer -> IO Frame
decodeAckFrame rbuf =
    Ack <$> decodeInt' rbuf <*> decodeInt' rbuf <*> decodeInt' rbuf <*> decodeInt' rbuf
