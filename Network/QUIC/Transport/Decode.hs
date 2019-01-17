{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC.Transport.Decode where

import Data.Bits
import Data.ByteString
import Data.Int (Int64)
import Network.ByteOrder

import Network.QUIC.Transport.Types

----------------------------------------------------------------

-- |
-- >>> decodeInt (dec16 "c2197c5eff14e88c")
-- 151288809941952652
-- >>> decodeInt (dec16 "9d7f3e7d")
-- 494878333
-- >>> decodeInt (dec16 "7bbd")
-- 15293
-- >>> decodeInt (dec16 "25")
-- 37
decodeInt :: ByteString -> IO Int64
decodeInt bs = withReadBuffer bs decodeInt'

decodeInt' :: ReadBuffer -> IO Int64
decodeInt' rbuf = do
    b0 <- read8 rbuf
--    let flag = (b0 .&. 0xc0) `shiftR` 6
    let flag = b0 `shiftR` 6
        b1 = fromIntegral (b0 .&. 0x3f)
    case flag of
      0 -> return b1
      1 -> loop b1 1
      2 -> loop b1 3
      _ -> loop b1 7
  where
    loop :: Int64 -> Int -> IO Int64
    loop r 0 = return r
    loop r n = do
        b <- fromIntegral <$> read8 rbuf
        loop (r*256 + b) (n - 1)

----------------------------------------------------------------

decodePacketNumber :: PacketNumber -> EncodedPacketNumber -> Int -> PacketNumber
decodePacketNumber largestPN truncatedPN pnNbits
  | candidatePN <= expectedPN - pnHwin = candidatePN + pnWin
  | candidatePN >  expectedPN + pnHwin
 && candidatePN >  pnWin               = candidatePN - pnWin
  | otherwise                          = candidatePN
  where
    expectedPN = largestPN + 1
    pnWin = 1 `shiftL` pnNbits
    pnHwin = pnWin `div` 2
    pnMask = pnWin - 1
    candidatePN = (expectedPN .&. complement pnMask)
              .|. fromIntegral truncatedPN

----------------------------------------------------------------

decodeFrames :: ByteString -> IO [Frame]
decodeFrames bs = withReadBuffer bs $ loop id
  where
    loop frames rbuf = do
        ok <- checkSpace rbuf 1
        if ok then do
            frame <- decodeFrame rbuf
            loop ((frame:) . frames) rbuf
          else
            return $ frames []

decodeFrame :: ReadBuffer -> IO Frame
decodeFrame rbuf = do
    b0 <- read8 rbuf
    case b0 of
      0x00 -> return Padding
      0x06 -> decodeCryptoFrame rbuf
      _x   -> error $ show _x

decodeCryptoFrame :: ReadBuffer -> IO Frame
decodeCryptoFrame rbuf = do
    off <- fromIntegral <$> decodeInt' rbuf
    len <- fromIntegral <$> decodeInt' rbuf
    cdata <- extractByteString rbuf len
    return $ Crypto off cdata

----------------------------------------------------------------

decodePacket :: ReadBuffer -> IO ()
decodePacket rbuf = do
    flags <- read8 rbuf
    _ <- if testBit flags 7 then do
        decodeLongHeader rbuf flags
      else
        decodeShortHeader rbuf flags
    return ()

decodePacketType :: RawFlags -> PacketType
decodePacketType flags = case flags .&. 0b00110000 of
    0b00000000 -> Initial
    0b00010000 -> RTT0
    0b00100000 -> Handshake
    _          -> Retry

decodeVersion :: Word32 -> Version
decodeVersion 0          = Negotiation
decodeVersion 0xff000011 = Draft17
decodeVersion w          = UnknownVersion w

decodeLongHeader :: ReadBuffer -> Word8 -> IO Header
decodeLongHeader rbuf flags = do
    version <- decodeVersion <$> read32 rbuf
    dcil <- fromIntegral <$> read8 rbuf
    scil <- fromIntegral <$> read8 rbuf
    dcID <- extractByteString rbuf dcil
    scID <- extractByteString rbuf scil
    case version of
      Negotiation -> return $ NegoHeader dcID scID
      Draft17     -> do
          let pt = decodePacketType flags
          return $ LongHeader pt flags version dcID scID
      UnknownVersion _ -> error "unknown version"

decodeShortHeader :: ReadBuffer -> Word8 -> IO Header
decodeShortHeader rbuf flags = undefined
