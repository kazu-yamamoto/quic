{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Recovery (
    onAckReceived
  , onPacketSent
  , onPacketReceived
  , onPacketNumberSpaceDiscarded
  , keepPlainPacket
  , releaseByRetry
  ) where

import Data.IORef
import GHC.Event
import Data.Sequence (Seq, (<|), ViewL(..), ViewR(..))
import qualified Data.Sequence as Seq

import Network.QUIC.Connection.Crypto
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.State
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

-- | Maximum reordering in packets before packet threshold loss
--   detection considers a packet lost.
kPacketThreshold :: PacketNumber
kPacketThreshold = 3

-- | Maximum reordering in time before time threshold loss detection
--   considers a packet lost.  Specified as an RTT multiplier.

kTimeThreshold :: Milliseconds -> Milliseconds
kTimeThreshold x = x + (x .>>. 3) -- 9/8

-- | Timer granularity.
kGranularity :: Milliseconds
kGranularity = Milliseconds 1

onPacketSent :: Connection -> EncryptionLevel -> PacketNumber -> PlainPacket -> PeerPacketNumbers -> Int -> IO ()
onPacketSent conn@Connection{..} lvl0 mypn ppkt ppns sentByes = do
    let lvl | lvl0 == RTT0Level = RTT1Level
            | otherwise         = lvl0
    onPacketSentCC conn sentByes
    now <- getTimeMillisecond
    modifyIORef' (lossDetection ! lvl) $ \ld -> ld {
        timeOfLastAckElicitingPacket = Just now
      }
    keepPlainPacket conn lvl mypn ppkt ppns sentByes
    setLossDetectionTimer conn

-- fixme
serverIsAtAntiAmplificationLimit :: Bool
serverIsAtAntiAmplificationLimit = False

onPacketReceived :: Connection -> IO ()
onPacketReceived conn = do
  -- If this datagram unblocks the server, arm the
  -- PTO timer to avoid deadlock.
  when serverIsAtAntiAmplificationLimit $ setLossDetectionTimer conn

onAckReceived :: Connection -> EncryptionLevel -> AckInfo -> Milliseconds -> IO ()
onAckReceived conn@Connection{..} lvl acks@(AckInfo largestAcked _ _) ackDelay = do
    ld@LossDetection{..} <- readIORef (lossDetection ! lvl)
    let lgstAcked = case largestAckedPacket of
          Nothing -> largestAcked
          Just la -> max largestAcked la
    writeIORef (lossDetection ! lvl) ld { largestAckedPacket = Just lgstAcked }

    newlyAckedPackets <- releaseByAcks conn lvl acks

    case Seq.viewr newlyAckedPackets of
      EmptyR -> return ()
      _ :> lastPkt -> do
        -- If the largest acknowledged is newly acked and
        -- at least one ack-eliciting was newly acked, update the RTT.
        when (spPacketNumber lastPkt == largestAcked) $ do
            latestRtt' <- getElapsedTimeMillisecond $ spTimeSent lastPkt
            let ackDelay' | lvl == RTT1Level = ackDelay
                          | otherwise        = 0
            updateRTT conn latestRtt' ackDelay'

        {- fimxe
        -- Process ECN information if present.
        if (ACK frame contains ECN information):
           ProcessECN(ack, lvl)
        -}

        lostPackets <- detectAndRemoveLostPackets conn lvl
        onPacketsLost conn lostPackets

        onPacketsAcked conn newlyAckedPackets

        -- Reset ptoCount unless the client is unsure if
        -- the server has validated the client's address.
        completed <- peerCompletedAddressValidation conn
        when completed $ modifyIORef' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }

        setLossDetectionTimer conn

updateRTT :: Connection -> Milliseconds -> Milliseconds -> IO ()
updateRTT Connection{..} latestRTT0 ackDelay0 = do
    rtt@RTT{..} <- readIORef recoveryRTT
    -- don't use latestRTT, use latestRTT0 instead

    -- minRTT ignores ack delay.
    let minRTT' = min minRTT latestRTT0
    -- Limit ackDelay by maxAckDelay
    -- ack_delay = min(Ack Delay in ACK Frame, max_ack_delay)
    let ackDelay = min ackDelay0 maxAckDelay
    -- Adjust for ack delay if plausible.
    -- adjusted_rtt = latest_rtt
    -- if (min_rtt + ack_delay < latest_rtt):
    --   adjusted_rtt = latest_rtt - ack_delay
    let adjustedRTT
          | latestRTT0 > minRTT + ackDelay = latestRTT0 - ackDelay
          | otherwise                      = latestRTT0

    -- rttvar_sample = abs(smoothed_rtt - adjusted_rtt)
    -- rttvar = 3/4 * rttvar + 1/4 * rttvar_sample
    let rttvar' = rttvar - (rttvar .>>. 2)
                + (abs (smoothedRTT - adjustedRTT) .>>. 2)
    -- smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
    let smoothedRTT' = smoothedRTT - (smoothedRTT .>>. 3)
                     + (adjustedRTT .>>. 3)
    let rtt' = rtt {
            latestRTT = latestRTT0
          , minRTT = minRTT'
          , smoothedRTT = smoothedRTT'
          , rttvar = rttvar'
          }
    writeIORef recoveryRTT rtt'

detectAndRemoveLostPackets :: Connection -> EncryptionLevel -> IO (Seq SentPacket)
detectAndRemoveLostPackets conn@Connection{..} lvl = do
    modifyIORef' (lossDetection ! lvl) $ \ld -> ld {
          lossTime = Nothing
        }
    RTT{..} <- readIORef recoveryRTT
    LossDetection{..} <- readIORef (lossDetection ! lvl)
    let Just largestAckedPacket' = largestAckedPacket
    let lossDelay0 = kTimeThreshold $ max latestRTT smoothedRTT

    -- Minimum time of kGranularity before packets are deemed lost.
    let lossDelay = max lossDelay0 kGranularity

    tm <- getPastTimeMillisecond lossDelay
    let predicate ent = spTimeSent ent <= tm
                     || (spPacketNumber ent <= largestAckedPacket' - kPacketThreshold)
    lostPackets <- releaseByPredicate conn lvl predicate

    mx <- findOldest conn lvl (\x -> spPacketNumber x <= largestAckedPacket')
    case mx of
      Nothing -> return ()
      Just x  -> do
          let next = spTimeSent x `addMillisecond` lossDelay
          modifyIORef' (lossDetection ! lvl) $ \ld -> ld {
                lossTime = Just next
              }

    return lostPackets

getLossTimeAndSpace :: Connection -> IO (Maybe (TimeMillisecond,EncryptionLevel))
getLossTimeAndSpace Connection{..} =
    loop [InitialLevel, HandshakeLevel, RTT1Level] Nothing
  where
    loop []     r = return r
    loop (l:ls) r = do
        mt <- lossTime <$> readIORef (lossDetection ! l)
        case mt of
          Nothing -> loop ls r
          Just t  -> case r of
            Nothing -> loop ls $ Just (t,l)
            Just (t0,_)
               | t < t0    -> loop ls $ Just (t,l)
               | otherwise -> loop ls r

getPtoTimeAndSpace :: Connection -> IO (Maybe (TimeMillisecond, EncryptionLevel))
getPtoTimeAndSpace conn@Connection{..} = do
    RTT{..} <- readIORef recoveryRTT
    CC{..} <- readIORef recoveryCC
    let duration = (smoothedRTT + max (4 * rttvar) kGranularity) * (2 ^ ptoCount)
    -- Arm PTO from now when there are no inflight packets.
    if bytesInFlight <= 0 then do
        pto <- getFutureTimeMillisecond duration
        lvl <- getEncryptionLevel conn
        return $ Just (pto, lvl)
      else
        loop duration [InitialLevel, HandshakeLevel, RTT1Level] Nothing
  where
    loop :: Milliseconds -> [EncryptionLevel] -> (Maybe (TimeMillisecond, EncryptionLevel)) -> IO (Maybe (TimeMillisecond, EncryptionLevel))
    loop _ [] r = return r
    loop duration (l:ls) r = do
        notInFlight <- noInFlightPacket conn l
        if notInFlight then
            loop duration ls r
          else if (l == RTT1Level) then do
            completed <- isConnectionEstablished conn
            if not completed then
                return r
              else do
                RTT{..} <- readIORef recoveryRTT
                let duration' = duration + maxAckDelay * (2 ^ ptoCount)
                loop1 duration' l ls r
          else
            loop1 duration l ls r
    loop1 duration l ls r = do
        LossDetection{..} <- readIORef (lossDetection ! l)
        case timeOfLastAckElicitingPacket of
          Nothing -> loop duration ls r
          Just t -> do
              let pto = t `addMillisecond` duration
              case r of
                Nothing -> loop duration ls $ Just (pto,l)
                Just (pto0,_)
                  | pto < pto0 -> loop duration ls $ Just (pto, l)
                  | otherwise  -> loop duration ls r

peerCompletedAddressValidation :: Connection -> IO Bool
-- For servers: assume clients validate the server's address implicitly.
peerCompletedAddressValidation conn
  | isServer conn = return True
-- For clients: servers complete address validation when a protected
-- packet is received.
-- has received Handshake ACK (fixme)
-- has received 1-RTT ACK     (fixme)
-- has received HANDSHAKE_DONE
peerCompletedAddressValidation conn = isConnectionEstablished conn

canceltLossDetectionTimer :: Connection -> IO ()
canceltLossDetectionTimer Connection{..} = do
    mk <- readIORef timeoutKey
    case mk of
      Nothing -> return ()
      Just k -> do
          mgr <- getSystemTimerManager
          unregisterTimeout mgr k

updateLossDetectionTimer :: Connection -> TimeMillisecond -> IO ()
updateLossDetectionTimer conn@Connection{..} tms = do
    mgr <- getSystemTimerManager
    mk <- readIORef timeoutKey
    case mk of
      Nothing -> return ()
      Just k -> unregisterTimeout mgr k
    Microseconds us <- getTimeoutInMicrosecond tms
    key <- registerTimeout mgr us $ onLossDetectionTimeout conn
    writeIORef timeoutKey $ Just key

setLossDetectionTimer :: Connection -> IO ()
setLossDetectionTimer conn@Connection{..} = do
    mtl <- getLossTimeAndSpace conn
    case mtl of
      Just (earliestLossTime,_) -> do
          -- Time threshold loss detection.
          updateLossDetectionTimer conn earliestLossTime
      Nothing ->
          if serverIsAtAntiAmplificationLimit then -- server is at anti-amplification limit
            -- The server's timer is not set if nothing can be sent.
            canceltLossDetectionTimer conn
          else do
              CC{..} <- readIORef recoveryCC
              completed <- peerCompletedAddressValidation conn
              if bytesInFlight > 0  && completed then
                  -- There is nothing to detect lost, so no timer is set.
                  -- However, the client needs to arm the timer if the
                  -- server might be blocked by the anti-amplification limit.
                  canceltLossDetectionTimer conn
                else do
                  -- Determine which PN space to arm PTO for.
                  mx <- getPtoTimeAndSpace conn
                  case mx of
                    Nothing -> return ()
                    Just (timeout, _) -> updateLossDetectionTimer conn timeout

onLossDetectionTimeout :: Connection -> IO ()
onLossDetectionTimeout conn@Connection{..} = do
    mtl <- getLossTimeAndSpace conn
    case mtl of
      Just (_, lvl) -> do
          -- Time threshold loss Detection
          lostPackets <- detectAndRemoveLostPackets conn lvl
          onPacketsLost conn lostPackets
          setLossDetectionTimer conn
      Nothing -> do
          CC{..} <- readIORef recoveryCC
          if bytesInFlight > 0 then do
              -- PTO. Send new data if available, else retransmit old data.
              -- If neither is available, send a single PING frame.
              mx <- getPtoTimeAndSpace conn
              case mx of
                Nothing -> return ()
                Just (_, lvl) -> putOutput conn $ OutControl lvl [Ping]
            else do
              -- Client sends an anti-deadlock packet: Initial is padded
              -- to earn more anti-amplification credit,
              -- a Handshake packet proves address ownership.
              lvl <- getEncryptionLevel conn
              putOutput conn $ OutControl lvl [Ping]

          modifyIORef' recoveryRTT $ \rtt -> rtt { ptoCount = ptoCount rtt + 1 }
          setLossDetectionTimer conn

----------------------------------------------------------------
----------------------------------------------------------------

-- | Minimum congestion window in bytes.
kMinimumWindow :: CC -> Int
kMinimumWindow CC{..} = maxDatagramSize .<<. 1

-- | Reduction in congestion window when a new loss event is detected.
kLossReductionFactor :: Int -> Int
kLossReductionFactor = (.>>. 1) -- 0.5

-- | Period of time for persistent congestion to be established,
-- specified as a PTO multiplier.
kPersistentCongestionThreshold :: Milliseconds -> Milliseconds
kPersistentCongestionThreshold (Milliseconds ms) = Milliseconds (3 * ms)

onPacketSentCC :: Connection -> Int -> IO ()
onPacketSentCC Connection{..} bytesSent =
    modifyIORef' recoveryCC $ \cc -> cc {
        bytesInFlight = bytesInFlight cc + bytesSent
      }

inCongestionRecovery :: TimeMillisecond -> Maybe TimeMillisecond -> Bool
inCongestionRecovery _ Nothing = False -- checkme
inCongestionRecovery sentTime (Just crst) = sentTime <= crst

onPacketsAcked :: Connection -> Seq SentPacket -> IO ()
onPacketsAcked Connection{..} ackedPackets = mapM_ control ackedPackets
  where
    control ackedPacket = do
        cc0@CC{..} <- readIORef recoveryCC
        let sentBytes = spSentBytes ackedPacket
            timeSent = spTimeSent ackedPacket
            cc1 = cc0 { bytesInFlight = bytesInFlight - sentBytes }
            isRecovery = inCongestionRecovery timeSent congestionRecoveryStartTime
            cc2
              -- Do not increase congestion window in recovery period.
              | isRecovery = cc1
              -- fixme: Do not increase congestion_window if application
              -- limited or flow control limited.
              --
              -- Slow start.
              | congestionWindow < ssthresh = cc1 {
                    congestionWindow =  congestionWindow + sentBytes
                  }
              -- Congestion avoidance.
              | otherwise = cc1 {
                    congestionWindow = congestionWindow + maxDatagramSize * sentBytes `div` congestionWindow
                  }
        writeIORef recoveryCC cc2

congestionEvent :: Connection -> TimeMillisecond -> IO ()
congestionEvent Connection{..} sentTime = do
    cc@CC{..} <- readIORef recoveryCC
    -- Start a new congestion event if packet was sent after the
    -- start of the previous congestion recovery period.
    unless (inCongestionRecovery sentTime congestionRecoveryStartTime) $ do
        now <- getTimeMillisecond
        let window0 = kLossReductionFactor congestionWindow
            window = max window0 $ kMinimumWindow cc
        writeIORef recoveryCC $ cc {
            congestionRecoveryStartTime = Just now
          , congestionWindow = window
          , ssthresh = window
          }
        -- A packet can be sent to speed up loss recovery.
        -- maybeSendOnePacket conn -- fixme

inPersistentCongestion :: Connection -> Seq SentPacket -> SentPacket -> IO Bool
inPersistentCongestion Connection{..} lostPackets' lstPkt =
    case Seq.viewl lostPackets' of
      EmptyL -> return False
      fstPkt :< _ -> do
          RTT{..} <- readIORef recoveryRTT
          let pto = smoothedRTT + max (rttvar .<<. 2) kGranularity + maxAckDelay
              Milliseconds congestionPeriod = kPersistentCongestionThreshold pto
              beg = spSentBytes fstPkt
              end = spSentBytes lstPkt
          return (fromIntegral congestionPeriod >= (end - beg))

onPacketsLost :: Connection -> Seq SentPacket -> IO ()
onPacketsLost conn@Connection{..} lostPackets = case Seq.viewr lostPackets of
  EmptyR -> return ()
  lostPackets' :> lastPkt -> do
    cc@CC{..} <- readIORef recoveryCC
    -- Remove lost packets from bytesInFlight.
    let sentBytes = sum $ fmap spSentBytes lostPackets

    congestionEvent conn $ spTimeSent lastPkt

    -- Collapse congestion window if persistent congestion
    persistent <- inPersistentCongestion conn lostPackets' lastPkt
    let window | persistent = kMinimumWindow cc
               | otherwise  = congestionWindow
    writeIORef recoveryCC $ cc {
        bytesInFlight = bytesInFlight - sentBytes
      , congestionWindow = window
      }

onPacketNumberSpaceDiscarded :: Connection -> EncryptionLevel -> IO ()
onPacketNumberSpaceDiscarded conn@Connection{..} lvl = do
    -- Remove any unacknowledged packets from flight.
    clearedPackets <- releaseByClear conn lvl
    let sentBytes = sum $ fmap spSentBytes clearedPackets
    modifyIORef' recoveryCC $ \cc -> cc {
        bytesInFlight = bytesInFlight cc - sentBytes
      }
    -- Reset the loss detection and PTO timer
    writeIORef (lossDetection ! lvl) initialLossDetection
    modifyIORef' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }
    setLossDetectionTimer conn

----------------------------------------------------------------
----------------------------------------------------------------

keepPlainPacket :: Connection -> EncryptionLevel -> PacketNumber -> PlainPacket -> PeerPacketNumbers -> Int -> IO ()
keepPlainPacket Connection{..} lvl pn ppkt ppns sentBytes = do
    tm <- getTimeMillisecond
    let ent = SentPacket {
            spPacketNumber = pn
          , spLevel        = lvl
          , spPlainPacket  = ppkt
          , spACKs         = ppns
          , spTimeSent     = tm
          , spSentBytes    = sentBytes
          }
    atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
      let db' = ent <| db
      in  (SentPackets db', ())

----------------------------------------------------------------

releaseByAcks :: Connection -> EncryptionLevel -> AckInfo -> IO (Seq SentPacket)
releaseByAcks conn lvl ackinfo = do
    let predicate = fromAckInfoToPred ackinfo . spPacketNumber
    releaseByPredicate conn lvl predicate

----------------------------------------------------------------

releaseByPredicate :: Connection -> EncryptionLevel -> (SentPacket -> Bool) -> IO (Seq SentPacket)
releaseByPredicate Connection{..} lvl predicate = do
    atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
       let (lostPackets, db') = Seq.partition predicate db
       in (SentPackets db', lostPackets)

----------------------------------------------------------------

releaseByClear :: Connection -> EncryptionLevel -> IO (Seq SentPacket)
releaseByClear Connection{..} lvl = do
    atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
        (emptySentPackets, db)

----------------------------------------------------------------

releaseByRetry :: Connection -> IO (Seq PlainPacket)
releaseByRetry conn = fmap spPlainPacket <$> releaseByClear conn InitialLevel

----------------------------------------------------------------

findOldest :: Connection -> EncryptionLevel -> (SentPacket -> Bool)
           -> IO (Maybe SentPacket)
findOldest Connection{..} lvl p = oldest <$> readIORef (sentPackets ! lvl)
  where
    oldest (SentPackets db) = case Seq.viewl $ Seq.filter p db of
      EmptyL -> Nothing
      x :< _ -> Just x

----------------------------------------------------------------

noInFlightPacket :: Connection -> EncryptionLevel -> IO Bool
noInFlightPacket Connection{..} lvl = do
    SentPackets db <- readIORef (sentPackets ! lvl)
    return $ Seq.null db
