module Network.QUIC.Packet.Number (
    encodePacketNumber
  , decodePacketNumber
  ) where

import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

-- |
--
-- >>> encodePacketNumber 0xabe8bc 0xac5c02 == (0x5c02,2)
-- True
-- >>> encodePacketNumber 0xa82f30ea 0xa82f9b32 == (0x9b32,2)
-- True
-- >>> encodePacketNumber 0xabe8bc 0xace8fe == (0xace8fe, 3)
-- True
encodePacketNumber :: PacketNumber -> PacketNumber -> (EncodedPacketNumber, Int)
encodePacketNumber largestPN pn = (diff, bytes)
  where
    enoughRange = (pn - largestPN) * 2
    (pnMask, bytes)
--      | enoughRange <      256 = (0x000000ff, 1)
      | enoughRange <    65536 = (0x0000ffff, 2)
      | enoughRange < 16777216 = (0x00ffffff, 3)
      | otherwise              = (0xffffffff, 4)
    diff = fromIntegral (pn .&. pnMask)

----------------------------------------------------------------

-- |
--
-- >>> decodePacketNumber 0xabe8bc 0x5c02 2 == 0xac5c02
-- True
-- >>> decodePacketNumber 0xa82f30ea 0x9b32 2 == 0xa82f9b32
-- True
-- >>> decodePacketNumber 0xabe8bc 0xace8fe 3 == 0xace8fe
-- True
decodePacketNumber :: PacketNumber -> EncodedPacketNumber -> Int -> PacketNumber
decodePacketNumber largestPN truncatedPN bytes
  | candidatePN <= expectedPN - pnHwin
 && candidatePN <  mx - pnWin          = candidatePN + pnWin
  | candidatePN >  expectedPN + pnHwin
 && candidatePN >= pnWin               = candidatePN - pnWin
  | otherwise                          = candidatePN
  where
    mx = 1 `shiftL` 62
    pnNbits = bytes * 8
    expectedPN = largestPN + 1
    pnWin = 1 `shiftL` pnNbits
    pnHwin = pnWin `div` 2
    pnMask = pnWin - 1
    candidatePN = (expectedPN .&. complement pnMask)
              .|. fromIntegral truncatedPN
