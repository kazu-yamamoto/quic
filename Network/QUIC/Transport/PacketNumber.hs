module Network.QUIC.Transport.PacketNumber where

import Network.QUIC.Imports
import Network.QUIC.Transport.Types


----------------------------------------------------------------

-- from draft18. We cannot use becase 32 is hard-coded in our impl.
-- encodePacketNumber 0xabe8bc 0xac5c02 == (0x5c02,16)
-- encodePacketNumber 0xa82f30ea 0xa82f9b32 == (0x9b32,16)
encodePacketNumber :: PacketNumber -> PacketNumber -> (EncodedPacketNumber, Int)
encodePacketNumber _largestPN pn = (diff, 32)
  where
    diff = fromIntegral (pn .&. 0xffffffff)


----------------------------------------------------------------

-- |
--
-- >>> decodePacketNumber 0xabe8bc 0x5c02 16 == 0xac5c02
-- True
-- >>> decodePacketNumber 0xa82f30ea 0x9b32 16 == 0xa82f9b32
-- True
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
