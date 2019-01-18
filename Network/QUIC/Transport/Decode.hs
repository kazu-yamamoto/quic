{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC.Transport.Decode where

import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Int (Int64)
import Network.ByteOrder

import Network.QUIC.TLS
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

decodePacket :: ByteString -> IO Packet
decodePacket pkt = withReadBuffer pkt $ \rbuf -> do
    flags <- read8 rbuf
    if testBit flags 7 then do
        decodeLongHeaderPacket rbuf flags
      else
        decodeShortHeaderPacket rbuf flags

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

decodeLongHeaderPacket :: ReadBuffer -> Word8 -> IO Packet
decodeLongHeaderPacket rbuf flags = do
    version <- decodeVersion <$> read32 rbuf
    cil <- fromIntegral <$> read8 rbuf
    let dcil = decodeCIL ((cil .&. 0b11110000) `shiftR` 4)
        scil = decodeCIL (cil .&. 0b1111)
    dcID <- extractByteString rbuf dcil
    scID <- extractByteString rbuf scil
    case version of
      Negotiation -> decodeVersionNegotiationPacket rbuf dcID scID
      Draft17     -> do
          case decodePacketType flags of
            Initial -> decodeInitialPacket rbuf flags version dcID scID
            _       -> undefined
      UnknownVersion _ -> error "unknown version"
  where
    decodeCIL 0 = 0
    decodeCIL n = n + 3

decodeInitialPacket :: ReadBuffer -> RawFlags -> Version -> DCID -> SCID -> IO Packet
decodeInitialPacket rbuf flags version dcID scID = do
    tokenLen <- fromIntegral <$> decodeInt' rbuf
    token <- extractByteString rbuf tokenLen
    len <- fromIntegral <$> decodeInt' rbuf
    let secret = clientInitialSecret cipher (CID dcID)
        hpKey = headerProtectionKey cipher secret
{-
    sample <- takeSample rbuf 16 -- fixme
    let Just (mask1,mask2) = B.uncons $ headerProtection cipher hpKey sample
        pnLen = fromIntegral ((flags `xor` mask1) .&. 0b11) + 1
    encodedPN <- extractByteString rbuf pnLen -- fixme
    encryptedPayload <- extractByteString rbuf len -- fixme: not copy
    let key = aeadKey cipher secret
        iv  = initialVector cipher secret
        header = undefined -- plain header as additional data
        pn = undefined -- plain packet number
        payload = decryptPayload cipher key iv pn encryptedPayload header
-}
    return $ InitialPacket version dcID scID token 1 {- fixme -} []
  where
    cipher = defaultCipher -- fixme

takeSample :: ReadBuffer -> Int -> IO ByteString
takeSample rbuf len = do
    ff rbuf 4
    sample <- extractByteString rbuf len
    ff rbuf (negate len)
    return sample

decodeVersionNegotiationPacket :: ReadBuffer -> DCID -> SCID -> IO Packet
decodeVersionNegotiationPacket rbuf dcID scID = do
    version <- decodeVersion <$> read32 rbuf
    -- fixme
    return $ VersionNegotiationPacket dcID scID [version]

decodeShortHeaderPacket :: ReadBuffer -> Word8 -> IO Packet
decodeShortHeaderPacket _rbuf _flags = undefined
