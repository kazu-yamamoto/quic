module Network.QUIC.Types.Constants where

import Network.QUIC.Types.Time

maximumUdpPayloadSize :: Int
maximumUdpPayloadSize = 2048 -- no global locking when allocating ByteString

----------------------------------------------------------------

defaultQUICPacketSize :: Int
defaultQUICPacketSize = 1200

-- Google paper: UDP payload size = 1350
--    http://www.audentia-gestion.fr/Recherche-Research-Google/46403.pdf

defaultQUICPacketSizeForIPv4 :: Int
defaultQUICPacketSizeForIPv4 = 1350

defaultQUICPacketSizeForIPv6 :: Int
defaultQUICPacketSizeForIPv6 = 1330

----------------------------------------------------------------

-- Not from spec. retry token is 128 sometime.
maximumQUICHeaderSize :: Int
maximumQUICHeaderSize = 256

----------------------------------------------------------------

idleTimeout :: Milliseconds
idleTimeout = Milliseconds 30000

----------------------------------------------------------------

-- | How much out-of-order CRYPTO data one encryption level will hold.
--
-- RFC 9000 section 7.5 asks an endpoint to buffer at least 4096 octets and
-- lets it hold more during the handshake.  4096 alone is too tight to be
-- useful: losing one packet early in a peer's flight leaves the rest of a
-- certificate chain waiting behind the gap, which is ordinary rather than
-- hostile.  This is well above the floor and still a bound.
cryptoBufferSize :: Int
cryptoBufferSize = 65536

----------------------------------------------------------------

-- | How many out-of-order fragments one stream will hold.
--
-- Flow control bounds the octets a stream may hold, not the pieces they
-- arrive in, and a piece costs far more than the octet it carries: a
-- ByteString, a heap node, a place in a sequence.  One-octet fragments at
-- scattered offsets therefore buy a peer two orders of magnitude on what its
-- window says it is spending.
--
-- Reordering in practice leaves a handful of gaps, not a thousand, so this is
-- far above anything real and still a bound.
maxReassFragments :: Int
maxReassFragments = 1024
