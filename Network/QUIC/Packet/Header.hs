{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC.Packet.Header (
    isLong
  , isShort
  , protectFlags
  , unprotectFlags
  , encodeLongHeaderFlags
  , encodeShortHeaderFlags
  , decodeLongHeaderPacketType
  , encodePktNumLength
  , decodePktNumLength
  , versionNegotiationPacketType
  , retryPacketType
  ) where

import Network.QUIC.Imports
import Network.QUIC.Types

{-# INLINE isLong #-}
isLong :: Word8 -> Bool
isLong flags = testBit flags 7

{-# INLINE isShort #-}
isShort :: Flags Protected -> Bool
isShort (Flags flags) = not $ testBit flags 7

----------------------------------------------------------------

unprotectFlags :: Flags Protected -> Word8 -> Flags Raw
unprotectFlags (Flags proFlags) mask1 = Flags flags
  where
    mask = mask1 .&. flagBits proFlags
    flags = proFlags `xor` mask

protectFlags :: Flags Raw -> Word8 -> Flags Protected
protectFlags (Flags flags) mask1 = Flags proFlags
  where
    mask = mask1 .&. flagBits flags
    proFlags = flags `xor` mask


{-# INLINE flagBits #-}
flagBits :: Word8 -> Word8
flagBits flags
  | isLong flags = 0b00001111 -- long header
  | otherwise    = 0b00011111 -- short header

----------------------------------------------------------------

randomizeQuicBit :: Word8 -> Bool -> IO Word8
randomizeQuicBit flags quicBit
  | quicBit = do
        r <- getRandomOneByte
        return ((flags .&. 0b10111111) .|. (r .&. 0b01000000))
  | otherwise = return flags

{-# INLINE encodeShortHeaderFlags #-}
encodeShortHeaderFlags :: Flags Raw -> Flags Raw -> Bool -> Bool -> IO (Flags Raw)
encodeShortHeaderFlags (Flags fg) (Flags pp) quicBit keyPhase =
    Flags <$> randomizeQuicBit flags quicBit
  where
    flags =          0b01000000
         .|. (fg .&. 0b00111100)
         .|. (pp .&. 0b00000011)
         .|. (if keyPhase then 0b00000100 else 0b00000000)

{-# INLINE encodeLongHeaderFlags #-}
encodeLongHeaderFlags :: Version -> LongHeaderPacketType -> Flags Raw -> Flags Raw -> Bool -> IO (Flags Raw)
encodeLongHeaderFlags ver typ (Flags fg) (Flags pp) quicBit =
    Flags <$> randomizeQuicBit flags quicBit
  where
    Flags tp = longHeaderPacketType ver typ
    flags =   tp
         .|. (fg .&. 0b00001100)
         .|. (pp .&. 0b00000011)

{-# INLINE longHeaderPacketType #-}
longHeaderPacketType :: Version -> LongHeaderPacketType -> Flags Raw
longHeaderPacketType Version2 InitialPacketType   = Flags 0b11010000
longHeaderPacketType Version2 RTT0PacketType      = Flags 0b11100000
longHeaderPacketType Version2 HandshakePacketType = Flags 0b11110000
longHeaderPacketType Version2 RetryPacketType     = Flags 0b11000000
longHeaderPacketType _        InitialPacketType   = Flags 0b11000000
longHeaderPacketType _        RTT0PacketType      = Flags 0b11010000
longHeaderPacketType _        HandshakePacketType = Flags 0b11100000
longHeaderPacketType _        RetryPacketType     = Flags 0b11110000

retryPacketType :: Version -> IO (Flags Raw)
retryPacketType Version2 = do
    r <- getRandomOneByte
    let flags = 0b11000000 .|. (r .&. 0b00001111)
    return $ Flags flags
retryPacketType _ = do
    r <- getRandomOneByte
    let flags = 0b11110000 .|. (r .&. 0b00001111)
    return $ Flags flags

versionNegotiationPacketType :: IO (Flags Raw)
versionNegotiationPacketType = do
    r <- getRandomOneByte
    let flags = 0b10000000 .|. (r .&. 0b01111111)
    return $ Flags flags

{-# INLINE decodeLongHeaderPacketType #-}
decodeLongHeaderPacketType :: Version -> Flags Protected -> LongHeaderPacketType
decodeLongHeaderPacketType Version2 (Flags flags) = case flags .&. 0b00110000 of
    0b00010000 -> InitialPacketType
    0b00100000 -> RTT0PacketType
    0b00110000 -> HandshakePacketType
    _          -> RetryPacketType
decodeLongHeaderPacketType _ (Flags flags) = case flags .&. 0b00110000 of
    0b00000000 -> InitialPacketType
    0b00010000 -> RTT0PacketType
    0b00100000 -> HandshakePacketType
    _          -> RetryPacketType

{-# INLINE encodePktNumLength #-}
encodePktNumLength :: Int -> Flags Raw
encodePktNumLength epnLen = Flags $ fromIntegral (epnLen - 1)

{-# INLINE decodePktNumLength #-}
decodePktNumLength :: Flags Raw -> Int
decodePktNumLength (Flags flags) = fromIntegral (flags .&. 0b11) + 1
