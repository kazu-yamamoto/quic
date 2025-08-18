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

reassembleQueueLimit :: Int
reassembleQueueLimit = 256 * 1024
