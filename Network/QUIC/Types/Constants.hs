module Network.QUIC.Types.Constants where

maximumUdpPayloadSize :: Int
maximumUdpPayloadSize = 2048 -- no global locking when allocating ByteString

----------------------------------------------------------------

-- minimum PMTU = 1024 + 256 = 1280
-- IPv4 payload = 1280 - 20 - 8 = 1252
-- IPv6 payload = 1280 - 40 - 8 = 1232

defaultQUICPacketSize :: Int
defaultQUICPacketSize = 1200

defaultQUICPacketSizeForIPv4 :: Int
defaultQUICPacketSizeForIPv4 = 1252

defaultQUICPacketSizeForIPv6 :: Int
defaultQUICPacketSizeForIPv6 = 1232

----------------------------------------------------------------

-- Not from spec. retry token is 128 sometime.
maximumQUICHeaderSize :: Int
maximumQUICHeaderSize = 256

