module Network.QUIC.Types.Recovery where

import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import Data.Set (Set)
import qualified Data.Set as Set

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.Packet
import Network.QUIC.Types.Time

----------------------------------------------------------------

newtype PeerPacketNumbers = PeerPacketNumbers (Set PacketNumber)
                          deriving (Eq, Show)

emptyPeerPacketNumbers :: PeerPacketNumbers
emptyPeerPacketNumbers = PeerPacketNumbers Set.empty

----------------------------------------------------------------

newtype SentPackets = SentPackets (Seq SentPacket) deriving Eq

emptySentPackets :: SentPackets
emptySentPackets = SentPackets Seq.empty

----------------------------------------------------------------

data SentPacketI = SentPacketI {
    spiPacketNumber      :: PacketNumber
  , spiEncryptionLevel   :: EncryptionLevel
  , spiPlainPacket       :: PlainPacket
  , spiPeerPacketNumbers :: PeerPacketNumbers
  , spiAckEliciting      :: Bool
  } deriving (Eq, Show)

data SentPacket = SentPacket {
    spSentPacketI :: SentPacketI
  , spTimeSent    :: TimeMicrosecond
  , spSentBytes   :: Int
  } deriving (Eq, Show)


spPacketNumber :: SentPacket -> PacketNumber
spPacketNumber = spiPacketNumber . spSentPacketI

spEncryptionLevel :: SentPacket -> EncryptionLevel
spEncryptionLevel = spiEncryptionLevel. spSentPacketI

spPlainPacket :: SentPacket -> PlainPacket
spPlainPacket = spiPlainPacket . spSentPacketI

spPeerPacketNumbers :: SentPacket -> PeerPacketNumbers
spPeerPacketNumbers = spiPeerPacketNumbers . spSentPacketI

spAckEliciting :: SentPacket -> Bool
spAckEliciting = spiAckEliciting . spSentPacketI

instance Ord SentPacket where
    x <= y = spPacketNumber x <= spPacketNumber y

----------------------------------------------------------------

data RTT = RTT {
  -- | The most recent RTT measurement made when receiving an ack for
  --   a previously unacked packet.
    latestRTT   :: Microseconds
  -- | The smoothed RTT of the connection.
  , smoothedRTT :: Microseconds
  -- | The RTT variation.
  , rttvar      :: Microseconds
  -- | The minimum RTT seen in the connection, ignoring ack delay.
  , minRTT      :: Microseconds
  -- | The maximum amount of time by which the receiver intends to
  --   delay acknowledgments for packets in the ApplicationData packet
  --   number space.  The actual ack_delay in a received ACK frame may
  --   be larger due to late timers, reordering, or lost ACK frames.
  , maxAckDelay1RTT :: Microseconds
  -- | The number of times a PTO has been sent without receiving
  --  an ack.
  , ptoCount :: Int
  } deriving Show

-- | The RTT used before an RTT sample is taken.
kInitialRTT :: Microseconds
kInitialRTT = Microseconds 333000

initialRTT :: RTT
initialRTT = RTT {
    latestRTT       = Microseconds 0
  , smoothedRTT     = kInitialRTT
  , rttvar          = kInitialRTT .>>. 1
  , minRTT          = Microseconds 0
  , maxAckDelay1RTT = Microseconds 0
  , ptoCount        = 0
  }

----------------------------------------------------------------

data CCMode = SlowStart
            | Avoidance
            | Recovery
            deriving (Eq)

instance Show CCMode where
    show SlowStart = "slow_start"
    show Avoidance = "congestion_avoidance"
    show Recovery  = "recovery"

data CC = CC {
  -- | The sum of the size in bytes of all sent packets that contain
  --   at least one ack-eliciting or PADDING frame, and have not been
  --   acked or declared lost.  The size does not include IP or UDP
  --   overhead, but does include the QUIC header and AEAD overhead.
  --   Packets only containing ACK frames do not count towards
  --   bytes_in_flight to ensure congestion control does not impede
  --   congestion feedback.
    bytesInFlight :: Int
  -- | Maximum number of bytes-in-flight that may be sent.
  , congestionWindow :: Int
  -- | The time when QUIC first detects congestion due to loss or ECN,
  --   causing it to enter congestion recovery.  When a packet sent
  --   after this time is acknowledged, QUIC exits congestion
  --   recovery.
  , congestionRecoveryStartTime :: Maybe TimeMicrosecond
  -- | Slow start threshold in bytes.  When the congestion window is
  --   below ssthresh, the mode is slow start and the window grows by
  --   the number of bytes acknowledged.
  , ssthresh :: Int
  -- | Records number of bytes acked, and used for incrementing
  --   the congestion window during congestion avoidance.
  , bytesAcked :: Int
  , numOfAckEliciting :: Int
  , ccMode :: CCMode
  } deriving Show

initialCC :: CC
initialCC = CC {
    bytesInFlight = 0
  , congestionWindow = 0
  , congestionRecoveryStartTime = Nothing
  , ssthresh = maxBound
  , bytesAcked = 0
  , numOfAckEliciting = 0
  , ccMode = SlowStart
  }

----------------------------------------------------------------

data LossDetection = LossDetection {
    largestAckedPacket           :: PacketNumber
  , previousAckInfo              :: AckInfo
  , timeOfLastAckElicitingPacket :: TimeMicrosecond
  , lossTime                     :: Maybe TimeMicrosecond
  } deriving Show

initialLossDetection :: LossDetection
initialLossDetection = LossDetection (-1) ackInfo0 timeMicrosecond0 Nothing

----------------------------------------------------------------

data MetricsDiff = MetricsDiff [(String,Int)]

----------------------------------------------------------------

data TimerType = LossTime
               | PTO
               deriving Eq

instance Show TimerType where
    show LossTime = "loss_time"
    show PTO      = "pto"

data TimerEvent = TimerSet
                | TimerExpired
                | TimerCancelled
                deriving Eq

instance Show TimerEvent where
    show TimerSet       = "set"
    show TimerExpired   = "expired"
    show TimerCancelled = "cancelled"

data TimerInfo = TimerInfo {
    timerTime  :: Either TimeMicrosecond Microseconds
  , timerLevel :: EncryptionLevel
  , timerType  :: TimerType
  , timerEvent :: TimerEvent
  } deriving Eq

timerInfo0 :: TimerInfo
timerInfo0 = TimerInfo (Right (Microseconds 0)) InitialLevel LossTime TimerCancelled

newtype Debug = Debug String

instance Show Debug where
    show (Debug msg) = msg
