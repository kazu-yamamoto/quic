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

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS

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

{-# INLINE encodeShortHeaderFlags #-}
encodeShortHeaderFlags :: Flags Raw -> Flags Raw -> Flags Raw
encodeShortHeaderFlags (Flags fg) (Flags pp) = Flags flags
  where
    flags =          0b01000000
         .|. (fg .&. 0b00111100)
         .|. (pp .&. 0b00000011)

{-# INLINE encodeLongHeaderFlags #-}
encodeLongHeaderFlags :: LongHeaderPacketType -> Flags Raw -> Flags Raw -> Flags Raw
encodeLongHeaderFlags typ (Flags fg) (Flags pp) = Flags flags
  where
    Flags tp = longHeaderPacketType typ
    flags =   tp
         .|. (fg .&. 0b00001100)
         .|. (pp .&. 0b00000011)

{-# INLINE longHeaderPacketType #-}
longHeaderPacketType :: LongHeaderPacketType -> Flags Raw
longHeaderPacketType InitialPacketType   = Flags 0b11000000
longHeaderPacketType RTT0PacketType      = Flags 0b11010000
longHeaderPacketType HandshakePacketType = Flags 0b11100000
longHeaderPacketType RetryPacketType     = Flags 0b11110000

retryPacketType :: IO (Flags Raw)
retryPacketType = do
    r <- getRandomOneByte
    let flags = 0b11110000 .|. (0b00001111 .&. r)
    return $ Flags flags

getRandomOneByte :: IO Word8
getRandomOneByte = BS.head <$> getRandomBytes 1

versionNegotiationPacketType :: IO (Flags Raw)
versionNegotiationPacketType = do
    r <- getRandomOneByte
    let flags = 0b10000000 .|. (0b01111111 .&. r)
    return $ Flags flags

{-# INLINE decodeLongHeaderPacketType #-}
decodeLongHeaderPacketType :: Flags Protected -> LongHeaderPacketType
decodeLongHeaderPacketType (Flags flags) = case flags .&. 0b00110000 of
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
