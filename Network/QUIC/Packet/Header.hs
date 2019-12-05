{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC.Packet.Header where

import Network.QUIC.Imports
import Network.QUIC.Types

{-# INLINE isLong #-}
isLong :: Word8 -> Bool
isLong flags = testBit flags 7

{-# INLINE isShort #-}
isShort :: Word8 -> Bool
isShort flags = not $ testBit flags 7

{-# INLINE flagBits #-}
flagBits :: Word8 -> Word8
flagBits flags
  | isLong flags = 0b00001111 -- long header
  | otherwise    = 0b00011111 -- short header

----------------------------------------------------------------

{-# INLINE encodeShortHeaderFlags #-}
encodeShortHeaderFlags :: RawFlags -> RawFlags -> RawFlags
encodeShortHeaderFlags fg pp =         0b01000000
                           .|. (fg .&. 0b00111100)
                           .|. (pp .&. 0b00000011)

{-# INLINE encodeLongHeaderFlags #-}
encodeLongHeaderFlags :: LongHeaderPacketType -> RawFlags -> RawFlags -> RawFlags
encodeLongHeaderFlags typ fg pp = longHeaderPacketType typ
                              .|. (fg .&. 0b00001100)

                              .|. (pp .&. 0b00000011)

{-# INLINE longHeaderPacketType #-}
longHeaderPacketType :: LongHeaderPacketType -> RawFlags
longHeaderPacketType InitialPacketType   = 0b11000000
longHeaderPacketType RTT0PacketType      = 0b11010000
longHeaderPacketType HandshakePacketType = 0b11100000
longHeaderPacketType RetryPacketType     = 0b11110000

retryPacketType :: RawFlags
retryPacketType = 0b11110000

versionNegotiationPacketType :: RawFlags
versionNegotiationPacketType = 0b10000000

{-# INLINE decodeLongHeaderPacketType #-}
decodeLongHeaderPacketType :: RawFlags -> LongHeaderPacketType
decodeLongHeaderPacketType flags = case flags .&. 0b00110000 of
    0b00000000 -> InitialPacketType
    0b00010000 -> RTT0PacketType
    0b00100000 -> HandshakePacketType
    _          -> RetryPacketType

{-# INLINE encodePktNumLength #-}
encodePktNumLength :: Int -> RawFlags
encodePktNumLength epnLen = fromIntegral (epnLen - 1)

{-# INLINE decodePktNumLength #-}
decodePktNumLength :: RawFlags -> Int
decodePktNumLength flags = fromIntegral (flags .&. 0b11) + 1
