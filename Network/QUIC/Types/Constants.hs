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

-- | How many unidirectional streams a peer may have open at once, to begin
--   with.
--
-- Three is what HTTP/3 needs and no more: a control stream and the two QPACK
-- streams (RFC 9114 Sec 6.2).  A peer given three can open nothing else --
-- not a push stream, not a stream of a type from an extension, and not one
-- of the reserved types it is meant to open now and then so that the types
-- stay extensible.  It was three here, so a client on these defaults could
-- never be pushed to, and an unknown stream type could never be tried on
-- one.
--
-- Ten leaves room for those without leaving the peer unbounded: the limit
-- counts what is open at once, and a stream gives its place back when it is
-- closed.
defaultMaxStreamsUni :: Int
defaultMaxStreamsUni = 10

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
