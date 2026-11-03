-- | The ACK Delay field.  The constructor is not exported: the field is
--   only read and written here, and only turned into time with the
--   exponent of the ACK's sender.
module Network.QUIC.Types.Delay (
    Delay,
    noDelay,
    ackDelayMicro,
    encodeDelay,
    decodeDelay,
) where

import Network.QUIC.Imports
import Network.QUIC.Types.Integer
import Network.QUIC.Types.Time

-- | The ACK Delay field as sent, in units of 2 ^ ack_delay_exponent
--   microseconds of the ACK's sender (RFC 9000 Sec 19.3).
newtype Delay = Delay Int deriving (Eq, Show)

-- | An ACK Delay of zero, whatever the exponent.
noDelay :: Delay
noDelay = Delay 0

-- | Microseconds from the ACK Delay field and the sender's exponent,
--   saturating rather than overflowing on a value out of range.
ackDelayMicro :: Int -> Delay -> Microseconds
ackDelayMicro e (Delay d)
    | d > maxBound `shiftR` e = Microseconds maxBound
    | otherwise = Microseconds $ d `shiftL` e

encodeDelay :: WriteBuffer -> Delay -> IO ()
encodeDelay wbuf (Delay d) = encodeInt' wbuf $ fromIntegral d

decodeDelay :: ReadBuffer -> IO Delay
decodeDelay rbuf = Delay . fromIntegral <$> decodeInt' rbuf
