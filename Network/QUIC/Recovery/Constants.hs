module Network.QUIC.Recovery.Constants where

import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Recovery.Types
import Network.QUIC.Types

timerGranularity :: Microseconds
timerGranularity = Microseconds 10000

-- | Maximum reordering in packets before packet threshold loss
--   detection considers a packet lost.
kPacketThreshold :: PacketNumber
kPacketThreshold = 3

-- | Maximum reordering in time before time threshold loss detection
--   considers a packet lost.  Specified as an RTT multiplier.

kTimeThreshold :: Microseconds -> Microseconds
kTimeThreshold x = x + (x !>>. 3) -- 9/8

-- | Timer granularity.
kGranularity :: Microseconds
-- kGranularity = Microseconds 5000
kGranularity = timerGranularity * 2

-- | Default limit on the initial bytes in flight.
kInitialWindow :: Int -> Int
--kInitialWindow pktSiz = min 14720 (10 * pktSiz)
kInitialWindow pktSiz = pktSiz !<<. 2 --  !<<. 1 is not good enough

-- | Minimum congestion window in bytes.
kMinimumWindow :: LDCC -> IO Int
kMinimumWindow ldcc = do
    siz <- getMaxPacketSize ldcc
    return (siz !<<. 2) -- !<<. 1 is not good enough

-- | Reduction in congestion window when a new loss event is detected.
kLossReductionFactor :: Int -> Int
kLossReductionFactor = (!>>. 1) -- 0.5

-- | Period of time for persistent congestion to be established,
-- specified as a PTO multiplier.
kPersistentCongestionThreshold :: Microseconds -> Microseconds
kPersistentCongestionThreshold (Microseconds us) = Microseconds (3 * us)
