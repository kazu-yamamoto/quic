{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Recovery.Types (
    SentPacket(..)
  , mkSentPacket
  , fixSentPacket
  , LostPacket(..)
  , SentPackets(..)
  , emptySentPackets
  , RTT(..)
  , initialRTT
  , CCMode(..)
  , CC(..)
  , initialCC
  , LossDetection(..)
  , initialLossDetection
  , MetricsDiff(..)
  , TimerType(..)
  , TimerSet(..)
  , TimerCancelled
  , TimerExpired
  , makeSentPackets
  , makeLossDetection
  , LDCC(..)
  , newLDCC
  , qlogSent
  , qlogMetricsUpdated
  , qlogPacketLost
  , qlogContestionStateUpdated
  , qlogLossTimerUpdated
  , qlogLossTimerCancelled
  , qlogLossTimerExpired
  ) where

import Control.Concurrent.STM
import Data.IORef
import Data.List (intersperse)
import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import GHC.Event
import System.Log.FastLogger

import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Qlog
import Network.QUIC.Types

----------------------------------------------------------------

data SentPacket = SentPacket {
    spPlainPacket       :: PlainPacket
  , spTimeSent          :: TimeMicrosecond
  , spSentBytes         :: Int
  , spEncryptionLevel   :: EncryptionLevel
  , spPacketNumber      :: PacketNumber
  , spPeerPacketNumbers :: PeerPacketNumbers
  , spAckEliciting      :: Bool
  } deriving (Eq, Show)

instance Ord SentPacket where
    x <= y = spPacketNumber x <= spPacketNumber y

newtype LostPacket = LostPacket SentPacket

mkSentPacket :: PacketNumber -> EncryptionLevel -> PlainPacket -> PeerPacketNumbers -> Bool -> SentPacket
mkSentPacket mypn lvl ppkt ppns ackeli = SentPacket {
    spPlainPacket       = ppkt
  , spTimeSent          = timeMicrosecond0
  , spSentBytes         = 0
  , spEncryptionLevel   = lvl
  , spPacketNumber      = mypn
  , spPeerPacketNumbers = ppns
  , spAckEliciting      = ackeli
  }

fixSentPacket :: SentPacket -> Int -> Int -> SentPacket
fixSentPacket spkt bytes padLen = spkt {
    spPlainPacket = if padLen /= 0 then addPadding padLen $ spPlainPacket spkt
                                   else spPlainPacket spkt
  , spSentBytes   = bytes
  }

addPadding :: Int -> PlainPacket -> PlainPacket
addPadding n (PlainPacket hdr plain) = PlainPacket hdr plain'
  where
    plain' = plain {
        plainFrames = plainFrames plain ++ [Padding n]
      }

----------------------------------------------------------------

newtype SentPackets = SentPackets (Seq SentPacket) deriving Eq

emptySentPackets :: SentPackets
emptySentPackets = SentPackets Seq.empty

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
    show Avoidance = "avoidance"
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

newtype MetricsDiff = MetricsDiff [(String,Int)]

----------------------------------------------------------------

data TimerType = LossTime
               | PTO
               deriving Eq

instance Show TimerType where
    show LossTime = "loss_time"
    show PTO      = "pto"

data TimerExpired = TimerExpired
data TimerCancelled = TimerCancelled
data TimerSet = TimerSet {
    timerTime  :: TimeMicrosecond
  , timerLevel :: EncryptionLevel
  , timerType  :: TimerType
  } deriving (Eq, Show)

type TimerQ = TQueue (Maybe TimerSet)

----------------------------------------------------------------

makeSentPackets :: IO (Array EncryptionLevel (IORef SentPackets))
makeSentPackets = do
    i1 <- newIORef emptySentPackets
    i2 <- newIORef emptySentPackets
    i3 <- newIORef emptySentPackets
    let lst = [(InitialLevel,i1),(HandshakeLevel,i2),(RTT1Level,i3)]
        arr = array (InitialLevel,RTT1Level) lst
    return arr

makeLossDetection :: IO (Array EncryptionLevel (IORef LossDetection))
makeLossDetection = do
    i1 <- newIORef initialLossDetection
    i2 <- newIORef initialLossDetection
    i3 <- newIORef initialLossDetection
    let lst = [(InitialLevel,i1),(HandshakeLevel,i2),(RTT1Level,i3)]
        arr = array (InitialLevel,RTT1Level) lst
    return arr

data LDCC = LDCC {
    ldccState         :: ConnState
  , ldccQlogger       :: QLogger
  , putRetrans        :: PlainPacket -> IO ()
  , recoveryRTT       :: IORef RTT
  , recoveryCC        :: TVar CC
  , spaceDiscarded    :: IOArray EncryptionLevel Bool
  , sentPackets       :: Array EncryptionLevel (IORef SentPackets)
  , lossDetection     :: Array EncryptionLevel (IORef LossDetection)
  , timerKey          :: IORef (Maybe TimeoutKey)
  , timerInfo         :: IORef (Maybe TimerSet)
  , lostCandidates    :: TVar SentPackets
  , ptoPing           :: TVar (Maybe EncryptionLevel)
  , speedingUp        :: IORef Bool
  , pktNumPersistent  :: IORef PacketNumber
  , peerPacketNumbers :: Array EncryptionLevel (IORef PeerPacketNumbers)
  , previousRTT1PPNs  :: IORef PeerPacketNumbers -- for RTT1
  , timerQ            :: TimerQ
  }

makePPN :: IO (Array EncryptionLevel (IORef PeerPacketNumbers))
makePPN = do
    ref1 <- newIORef emptyPeerPacketNumbers
    ref2 <- newIORef emptyPeerPacketNumbers
    ref3 <- newIORef emptyPeerPacketNumbers
    -- using the ref for RTT0Level and RTT1Level
    let lst = [(InitialLevel,   ref1)
              ,(RTT0Level,      ref3)
              ,(HandshakeLevel, ref2)
              ,(RTT1Level,      ref3)]
        arr = array (InitialLevel,RTT1Level) lst
    return arr

newLDCC :: ConnState -> QLogger -> (PlainPacket -> IO ()) -> IO LDCC
newLDCC cs qLog put = LDCC cs qLog put
    <$> newIORef initialRTT
    <*> newTVarIO initialCC
    <*> newArray (InitialLevel,RTT1Level) False
    <*> makeSentPackets
    <*> makeLossDetection
    <*> newIORef Nothing
    <*> newIORef Nothing
    <*> newTVarIO emptySentPackets
    <*> newTVarIO Nothing
    <*> newIORef False
    <*> newIORef maxBound
    <*> makePPN
    <*> newIORef emptyPeerPacketNumbers
    <*> newTQueueIO

instance KeepQlog LDCC where
    keepQlog = ldccQlogger

instance Connector LDCC where
    getRole            = role . ldccState
    getEncryptionLevel = readTVarIO . encryptionLevel . ldccState
    getMaxPacketSize   = readIORef  . maxPacketSize   . ldccState
    getConnectionState = readTVarIO . connectionState . ldccState
    getPacketNumber    = readIORef  . packetNumber    . ldccState

----------------------------------------------------------------

instance Qlog SentPacket where
    qlog SentPacket{..} = "{\"raw\":{\"length\":" <> sw spSentBytes <> "},\"header\":{\"packet_type\":\"" <> toLogStr (packetType hdr) <> "\",\"packet_number\":\"" <> sw plainPacketNumber <> "\",\"dcid\":\"" <> sw (headerMyCID hdr) <> "\"},\"frames\":" <> "[" <> foldr1 (<>) (intersperse "," (map qlog plainFrames)) <> "]" <> "}"
      where
        PlainPacket hdr Plain{..} = spPlainPacket

instance Qlog LostPacket where
    qlog (LostPacket SentPacket{..}) =
        "{\"header\":{\"packet_type\":\"" <> toLogStr (packetType hdr) <> "\"" <>
        ",\"packet_number\":" <> sw spPacketNumber <>
        "}}"
      where
        PlainPacket hdr _ = spPlainPacket

instance Qlog MetricsDiff where
    qlog (MetricsDiff []) = "{}"
    qlog (MetricsDiff (x:xs)) = "{" <> tv0 x <> foldr tv "" xs <> "}"
      where
        tv0 (tag,val)    =  "\"" <> toLogStr tag <> "\":" <> sw val
        tv (tag,val) pre = ",\"" <> toLogStr tag <> "\":" <> sw val <> pre

instance Qlog CCMode where
    qlog mode = "{\"new\":\"" <> sw mode <> "\"}"

instance Qlog TimerCancelled where
    qlog TimerCancelled = "{\"event_type\":\"cancelled\"}"

instance Qlog TimerExpired where
    qlog TimerExpired   = "{\"event_type\":\"expired\"}"

instance Qlog (TimerSet,Microseconds) where
    qlog (TimerSet{..},us) = "{\"event_type\":\"set\"" <>
                             ",\"timer_type\":\"" <> sw timerType <> "\"" <>
                             ",\"packet_number_space\":\"" <> packetNumberSpace timerLevel <> "\"" <>
                             ",\"delta\":" <> delta us <>
                             "}"

packetNumberSpace :: EncryptionLevel -> LogStr
packetNumberSpace InitialLevel   = "initial"
packetNumberSpace RTT0Level      = "application_data"
packetNumberSpace HandshakeLevel = "handshake"
packetNumberSpace RTT1Level      = "application_data"

delta :: Microseconds -> LogStr
delta (Microseconds n) = sw n

qlogSent :: KeepQlog q => q -> SentPacket -> TimeMicrosecond -> IO ()
qlogSent q pkt tim = keepQlog q $ QSent (qlog pkt) tim

qlogMetricsUpdated :: KeepQlog q => q -> MetricsDiff -> IO ()
qlogMetricsUpdated q m = do
    tim <- getTimeMicrosecond
    keepQlog q $ QMetricsUpdated (qlog m) tim

qlogPacketLost :: KeepQlog q => q -> LostPacket -> IO ()
qlogPacketLost q lpkt = do
    tim <- getTimeMicrosecond
    keepQlog q $ QPacketLost (qlog lpkt) tim

qlogContestionStateUpdated :: KeepQlog q => q -> CCMode -> IO ()
qlogContestionStateUpdated q mode = do
    tim <- getTimeMicrosecond
    keepQlog q $ QCongestionStateUpdated (qlog mode) tim

qlogLossTimerUpdated :: KeepQlog q => q -> (TimerSet,Microseconds) -> IO ()
qlogLossTimerUpdated q tmi = do
    tim <- getTimeMicrosecond
    keepQlog q $ QLossTimerUpdated (qlog tmi) tim

qlogLossTimerCancelled :: KeepQlog q => q -> IO ()
qlogLossTimerCancelled q = do
    tim <- getTimeMicrosecond
    keepQlog q $ QLossTimerUpdated (qlog TimerCancelled) tim

qlogLossTimerExpired :: KeepQlog q => q -> IO ()
qlogLossTimerExpired q = do
    tim <- getTimeMicrosecond
    keepQlog q $ QLossTimerUpdated (qlog TimerExpired) tim
