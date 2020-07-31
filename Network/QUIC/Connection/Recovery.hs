{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}

module Network.QUIC.Connection.Recovery (
    onAckReceived
  , onPacketSent
  , onPacketReceived
  , onPacketNumberSpaceDiscarded
  , releaseByRetry
  , checkWindowOpenSTM
  , takePingSTM
  , setInitialCongestionWindow
  , resender
  ) where

import Control.Concurrent.STM
import Data.Sequence (Seq, (|>), (><), ViewL(..), ViewR(..))
import qualified Data.Sequence as Seq
import Data.UnixTime
import GHC.Event hiding (new)

import Network.QUIC.Connection.Crypto
import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.Qlog
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.State
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Timeout
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
kGranularity = Milliseconds 5

onPacketSent :: Connection -> SentPacket -> IO ()
onPacketSent conn@Connection{..} sentPacket = do
    let lvl0 = spEncryptionLevel $ spSentPacketI sentPacket
    let lvl | lvl0 == RTT0Level = RTT1Level
            | otherwise         = lvl0
    onPacketSentCC conn sentPacket
    when (spAckEliciting $ spSentPacketI sentPacket) $
        atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
            timeOfLastAckElicitingPacket = spTimeSent sentPacket
          }
    atomicModifyIORef'' (sentPackets ! lvl) $
        \(SentPackets db) -> SentPackets (db |> sentPacket)
    setLossDetectionTimer conn

-- fixme
serverIsAtAntiAmplificationLimit :: Bool
serverIsAtAntiAmplificationLimit = False

onPacketReceived :: Connection -> EncryptionLevel -> PacketNumber -> IO ()
onPacketReceived conn lvl pn = do
  addPeerPacketNumbers conn lvl pn
  -- If this datagram unblocks the server, arm the
  -- PTO timer to avoid deadlock.
  when serverIsAtAntiAmplificationLimit $ setLossDetectionTimer conn

onAckReceived :: Connection -> EncryptionLevel -> AckInfo -> Milliseconds -> IO ()
onAckReceived conn@Connection{..} lvl ackInfo@(AckInfo largestAcked _ _) ackDelay = do
    changed <- atomicModifyIORef' (lossDetection ! lvl) update
    when changed $ do
        let predicate = fromAckInfoToPred ackInfo . spPacketNumber . spSentPacketI
        releaseLostCandidates conn lvl predicate >>= updateCC
        releaseByPredicate    conn lvl predicate >>= updateRTTandCC
    {- fimxe
    -- Process ECN information if present.
       if (ACK frame contains ECN information):
         ProcessECN(ack, lvl)
    -}
    lostPackets <- detectAndRemoveLostPackets conn lvl
    appendLostCandidates conn lostPackets
  where
    update ld@LossDetection{..} = (ld', changed)
      where
        ld' = ld { largestAckedPacket = max largestAckedPacket largestAcked
                 , previousAckInfo = ackInfo
                 }
        changed = previousAckInfo /= ackInfo
    updateRTTandCC newlyAckedPackets = case Seq.viewr newlyAckedPackets of
      EmptyR -> return ()
      _ :> lastPkt -> do
          -- If the largest acknowledged is newly acked and
          -- at least one ack-eliciting was newly acked, update the RTT.
          when (spPacketNumber (spSentPacketI lastPkt) == largestAcked
             && any (spAckEliciting . spSentPacketI) newlyAckedPackets) $ do
              rtt <- getElapsedTimeMillisecond $ spTimeSent lastPkt
              let latestRtt = max rtt kGranularity
              updateRTT conn lvl latestRtt ackDelay

          updateCC newlyAckedPackets

    updateCC newlyAckedPackets
      | newlyAckedPackets == Seq.empty = return ()
      | otherwise = do
          onPacketsAcked conn newlyAckedPackets

          -- Sec 6.2.1. Computing PTO
          -- "The PTO backoff factor is reset when an acknowledgement is
          --  received, except in the following case. A server might
          --  take longer to respond to packets during the handshake
          --  than otherwise. To protect such a server from repeated
          --  client probes, the PTO backoff is not reset at a client
          --  that is not yet certain that the server has finished
          --  validating the client's address."
          completed <- peerCompletedAddressValidation conn
          when completed $ do
              atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }
              readIORef recoveryRTT >>= qlogMetricsUpdated conn

          setLossDetectionTimer conn

updateRTT :: Connection -> EncryptionLevel -> Milliseconds -> Milliseconds -> IO ()
updateRTT conn@Connection{..} lvl latestRTT0 ackDelay0 = do
  atomicModifyIORef'' recoveryRTT $ \rtt@RTT{..} ->
    -- don't use latestRTT, use latestRTT0 instead
    if latestRTT == Milliseconds 0 then -- first time
        -- Overwriting the initial value with the first sample.
        -- Initial value was used to calculate PTO.
        --
        -- smoothed_rtt = rtt_sample
        -- rttvar = rtt_sample / 2
        let rtt' = rtt {
                latestRTT   = latestRTT0
              , minRTT      = latestRTT0
              , smoothedRTT = latestRTT0
              , rttvar      = latestRTT0 `unsafeShiftR` 1
              }
        in rtt'
      else
        -- minRTT ignores ack delay.
        let minRTT' = min minRTT latestRTT0
        -- Limit ack_delay by max_ack_delay
        -- ack_delay = min(Ack Delay in ACK Frame, max_ack_delay)
            ackDelay = min ackDelay0 $ getMaxAckDelay (Just lvl) maxAckDelay1RTT
        -- Adjust for ack delay if plausible.
        -- adjusted_rtt = latest_rtt
        -- if (min_rtt + ack_delay < latest_rtt):
        --   adjusted_rtt = latest_rtt - ack_delay
            adjustedRTT
              | latestRTT0 > minRTT + ackDelay = latestRTT0 - ackDelay
              | otherwise                      = latestRTT0

        -- rttvar_sample = abs(smoothed_rtt - adjusted_rtt)
        -- rttvar = 3/4 * rttvar + 1/4 * rttvar_sample
            rttvar' = rttvar - (rttvar .>>. 2)
                    + (abs (smoothedRTT - adjustedRTT) .>>. 2)
        -- smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
            smoothedRTT' = smoothedRTT - (smoothedRTT .>>. 3)
                         + (adjustedRTT .>>. 3)
            rtt' = rtt {
                latestRTT = latestRTT0
              , minRTT = minRTT'
              , smoothedRTT = smoothedRTT'
              , rttvar = rttvar'
              }
        in rtt'
  readIORef recoveryRTT >>= qlogMetricsUpdated conn

detectAndRemoveLostPackets :: Connection -> EncryptionLevel -> IO (Seq SentPacket)
detectAndRemoveLostPackets conn@Connection{..} lvl = do
    lae <- timeOfLastAckElicitingPacket <$> readIORef (lossDetection ! lvl)
    when (lae == timeMillisecond0) $
        qlogDebug conn $ Debug "detectAndRemoveLostPackets: timeOfLastAckElicitingPacket: 0"
    atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
          lossTime = Nothing
        }
    RTT{..} <- readIORef recoveryRTT
    LossDetection{..} <- readIORef (lossDetection ! lvl)
    when (largestAckedPacket == -1) $
        qlogDebug conn $ Debug "detectAndRemoveLostPackets: largestAckedPacket: -1"
    -- Sec 6.1.2. Time Threshold
    -- max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)
    let lossDelay0 = kTimeThreshold $ max latestRTT smoothedRTT
    let lossDelay = max lossDelay0 kGranularity

    tm <- getPastTimeMillisecond lossDelay
    let predicate ent = (spPacketNumber (spSentPacketI ent) <= largestAckedPacket - kPacketThreshold)
                     || (spTimeSent ent <= tm)
    lostPackets <- releaseByPredicate conn lvl predicate

    mx <- findOldest conn lvl (\x -> spPacketNumber (spSentPacketI x) <= largestAckedPacket)
    case mx of
      -- No gap packet. PTO turn.
      Nothing -> return ()
      -- There are gap packets which are not declared lost.
      -- Set lossTime to next.
      Just x  -> do
          let next = spTimeSent x `addMillisecond` lossDelay
          atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
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

getMaxAckDelay :: Maybe EncryptionLevel -> Milliseconds -> Milliseconds
getMaxAckDelay Nothing n = n
getMaxAckDelay (Just lvl) n
  | lvl `elem` [InitialLevel,HandshakeLevel] = 0
  | otherwise                                = n

-- Sec 6.2.1. Computing PTO
-- PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
calcPTO :: RTT -> Maybe EncryptionLevel -> Milliseconds
calcPTO RTT{..} mlvl = smoothedRTT + max (rttvar .<<. 2) kGranularity + dly
  where
    dly = getMaxAckDelay mlvl maxAckDelay1RTT

backOff :: Milliseconds -> Int -> Milliseconds
backOff n cnt = n * (2 ^ cnt)

getPtoTimeAndSpace :: Connection -> IO (Maybe (TimeMillisecond, EncryptionLevel))
getPtoTimeAndSpace conn@Connection{..} = do
    -- Arm PTO from now when there are no inflight packets.
    CC{..} <- readTVarIO recoveryCC
    if bytesInFlight <= 0 then do
        validated <- peerCompletedAddressValidation conn
        if validated then do
            connDebugLog "getPtoTimeAndSpace: validated"
            return Nothing
          else do
            rtt <- readIORef recoveryRTT
            lvl <- getEncryptionLevel conn
            let pto = backOff (calcPTO rtt $ Just lvl) (ptoCount rtt)
            ptoTime <- getFutureTimeMillisecond pto
            return $ Just (ptoTime, lvl)
      else do
        completed <- isConnectionEstablished conn
        let lvls | completed = [InitialLevel, HandshakeLevel, RTT1Level]
                 | otherwise = [InitialLevel, HandshakeLevel]
        loop lvls Nothing
  where
    loop :: [EncryptionLevel] -> (Maybe (TimeMillisecond, EncryptionLevel)) -> IO (Maybe (TimeMillisecond, EncryptionLevel))
    loop [] r = return r
    loop (l:ls) r = do
        notInFlight <- noInFlightPacket conn l
        if notInFlight then
            loop ls r
          else do
            LossDetection{..} <- readIORef (lossDetection ! l)
            if timeOfLastAckElicitingPacket == timeMillisecond0 then
                loop ls r
              else do
                  rtt <- readIORef recoveryRTT
                  let pto = backOff (calcPTO rtt $ Just l) (ptoCount rtt)
                  let ptoTime = timeOfLastAckElicitingPacket `addMillisecond` pto
                  case r of
                    Nothing -> loop ls $ Just (ptoTime,l)
                    Just (ptoTime0,_)
                      | ptoTime < ptoTime0 -> loop ls $ Just (ptoTime, l)
                      | otherwise          -> loop ls r

-- Sec 6.2.1. Computing PTO
-- "That is, a client does not reset the PTO backoff factor on
--  receiving acknowledgements until it receives a HANDSHAKE_DONE
--  frame or an acknowledgement for one of its Handshake or 1-RTT
--  packets."
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

cancelLossDetectionTimer :: Connection -> IO ()
cancelLossDetectionTimer conn@Connection{..} = do
    mk <- atomicModifyIORef' timerKey $ \oldkey -> (Nothing, oldkey)
    case mk of
      Nothing -> return ()
      Just k -> do
          mgr <- getSystemTimerManager
          unregisterTimeout mgr k
          oldtmi <- readIORef timerInfo
          let tmi = oldtmi { timerEvent = TimerCancelled }
          writeIORef timerInfo tmi
          qlogLossTimerUpdated conn tmi

updateLossDetectionTimer :: Connection -> TimerInfo -> IO ()
updateLossDetectionTimer conn@Connection{..} tmi = do
    oldtmi <- readIORef timerInfo
    when (timerTime oldtmi /= timerTime tmi) $ do
        mgr <- getSystemTimerManager
        let Left tim = timerTime tmi
        Microseconds us <- getTimeoutInMicrosecond tim
        if us <= 0 then do
            qlogDebug conn $ Debug "updateLossDetectionTimer: minus"
            cancelLossDetectionTimer conn
          else do
            key <- registerTimeout mgr us (onLossDetectionTimeout conn)
            mk <- atomicModifyIORef' timerKey $ \oldkey -> (Just key, oldkey)
            case mk of
              Nothing -> return ()
              Just k -> unregisterTimeout mgr k
            let duration = Milliseconds (fromIntegral us `div` 1000)
                newtmi = tmi { timerTime = Right duration }
            writeIORef timerInfo newtmi
            qlogLossTimerUpdated conn newtmi

setLossDetectionTimer :: Connection -> IO ()
setLossDetectionTimer conn@Connection{..} = do
    mtl <- getLossTimeAndSpace conn
    case mtl of
      Just (earliestLossTime,lvl) -> do
          -- Time threshold loss detection.
          let tmi = TimerInfo (Left earliestLossTime) lvl LossTime TimerSet
          updateLossDetectionTimer conn tmi
      Nothing ->
          if serverIsAtAntiAmplificationLimit then -- server is at anti-amplification limit
            -- The server's timer is not set if nothing can be sent.
              cancelLossDetectionTimer conn
            else do
              CC{..} <- readTVarIO recoveryCC
              validated <- peerCompletedAddressValidation conn
              if numOfAckEliciting <= 0 && validated then
                  -- There is nothing to detect lost, so no timer is set.
                  -- However, the client needs to arm the timer if the
                  -- server might be blocked by the anti-amplification limit.
                  cancelLossDetectionTimer conn
                else do
                  -- Determine which PN space to arm PTO for.
                  mx <- getPtoTimeAndSpace conn
                  case mx of
                    Nothing -> cancelLossDetectionTimer conn
                    Just (ptoTime, lvl) -> do
                        let tmi = TimerInfo (Left ptoTime) lvl PTO TimerSet
                        updateLossDetectionTimer conn tmi

-- The only time the PTO is armed when there are no bytes in flight is
-- when it's a client and it's unsure if the server has completed
-- address validation.
onLossDetectionTimeout :: Connection -> IO ()
onLossDetectionTimeout conn@Connection{..} = do
    open <- isConnectionOpen conn
    when open $ do
        tmi <- readIORef timerInfo
        qlogLossTimerUpdated conn tmi { timerEvent = TimerExpired }
        let lvl = timerLevel tmi
        case timerType tmi of
          LossTime -> do
              -- Time threshold loss Detection
              lostPackets <- detectAndRemoveLostPackets conn lvl
              when (null lostPackets) $ connDebugLog "onLossDetectionTimeout: null"
              onPacketsLost conn lostPackets
              retransmit conn lostPackets
              setLossDetectionTimer conn
          PTO -> do
              CC{..} <- readTVarIO recoveryCC
              if bytesInFlight > 0 then do
                  -- PTO. Send new data if available, else retransmit old data.
                  -- If neither is available, send a single PING frame.
                  sendPing conn lvl
                else do
                  -- Client sends an anti-deadlock packet: Initial is padded
                  -- to earn more anti-amplification credit,
                  -- a Handshake packet proves address ownership.
                  validated <- peerCompletedAddressValidation conn
                  when (validated) $ connDebugLog "onLossDetectionTimeout: RTT1"
                  lvl' <- getEncryptionLevel conn -- fixme
                  sendPing conn lvl'

              atomicModifyIORef'' recoveryRTT $ \rtt ->
                rtt { ptoCount = ptoCount rtt + 1 }
              readIORef recoveryRTT >>= qlogMetricsUpdated conn
              setLossDetectionTimer conn

sendPing :: Connection -> EncryptionLevel -> IO ()
sendPing Connection{..} lvl = do
    now <- getTimeMillisecond
    atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
        timeOfLastAckElicitingPacket = now
      }
    atomically $ writeTVar ptoPing $ Just lvl

----------------------------------------------------------------
----------------------------------------------------------------

-- | Default limit on the initial bytes in flight.
kInitialWindow :: Int -> Int
kInitialWindow pktSiz = min 14720 (10 * pktSiz)
--kInitialWindow pktSiz = 2 * pktSiz

-- | Minimum congestion window in bytes.
kMinimumWindow :: Connection -> IO Int
kMinimumWindow Connection{..} = do
    siz <- readIORef maxPacketSize
    return (siz .<<. 3) -- 2 is not good enough

-- | Reduction in congestion window when a new loss event is detected.
kLossReductionFactor :: Int -> Int
kLossReductionFactor = (.>>. 1) -- 0.5

-- | Period of time for persistent congestion to be established,
-- specified as a PTO multiplier.
kPersistentCongestionThreshold :: Milliseconds -> Milliseconds
kPersistentCongestionThreshold (Milliseconds ms) = Milliseconds (3 * ms)

onPacketSentCC :: Connection -> SentPacket -> IO ()
onPacketSentCC conn@Connection{..} sentPacket = do
    atomically $ modifyTVar' recoveryCC $ \cc -> cc {
        bytesInFlight = bytesInFlight cc + bytesSent
      , numOfAckEliciting = numOfAckEliciting cc + countAckEli sentPacket
      }
    readTVarIO recoveryCC >>= qlogMetricsUpdated conn
  where
    bytesSent = spSentBytes sentPacket

countAckEli :: SentPacket -> Int
countAckEli sentPacket
  | spAckEliciting (spSentPacketI sentPacket) = 1
  | otherwise                                 = 0

inCongestionRecovery :: TimeMillisecond -> Maybe TimeMillisecond -> Bool
inCongestionRecovery _ Nothing = False -- checkme
inCongestionRecovery sentTime (Just crst) = sentTime <= crst

onPacketsAcked :: Connection -> Seq SentPacket -> IO ()
onPacketsAcked conn@Connection{..} ackedPackets = do
    maxPktSiz <- readIORef maxPacketSize
    oldcc <- readTVarIO recoveryCC
    atomically $ modifyTVar' recoveryCC $ modify maxPktSiz
    newcc <- readTVarIO recoveryCC
    qlogMetricsUpdated conn newcc
    when (ccMode oldcc /= ccMode newcc) $
      qlogContestionStateUpdated conn $ ccMode newcc
  where
    modify maxPktSiz cc@CC{..} = cc {
           bytesInFlight = bytesInFlight'
         , congestionWindow = congestionWindow'
         , bytesAcked = bytesAcked'
         , ccMode = ccMode'
         , numOfAckEliciting = numOfAckEliciting'
         }
      where
        (bytesInFlight',congestionWindow',bytesAcked',ccMode',numOfAckEliciting') =
              foldl' (.+) (bytesInFlight,congestionWindow,bytesAcked,ccMode,numOfAckEliciting) ackedPackets
        (bytes,cwin,acked,_,cnt) .+ sp@SentPacket{..} = (bytes',cwin',acked',mode',cnt')
          where
            isRecovery = inCongestionRecovery spTimeSent congestionRecoveryStartTime
            bytes' = bytes - spSentBytes
            ackedA = acked + spSentBytes
            cnt' = cnt - countAckEli sp
            (cwin',acked',mode')
              -- Do not increase congestion window in recovery period.
              | isRecovery      = (cwin, acked, Recovery)
              -- fixme: Do not increase congestion_window if application
              -- limited or flow control limited.
              --
              -- Slow start.
              | cwin < ssthresh = (cwin + spSentBytes, acked, SlowStart)
              -- Congestion avoidance.
              -- In this implementation, maxPktSiz == spSentBytes.
              -- spSentBytes is large enough, so we don't care
              -- the roundup issue of `div`.
              | ackedA >= cwin  = (cwin + maxPktSiz, ackedA - cwin, Avoidance)
              | otherwise       = (cwin, ackedA, Avoidance)

onNewCongestionEvent :: Connection -> TimeMillisecond -> IO ()
onNewCongestionEvent conn@Connection{..} sentTime = do
    CC{congestionRecoveryStartTime} <- readTVarIO recoveryCC
    -- Start a new congestion event if packet was sent after the
    -- start of the previous congestion recovery period.
    unless (inCongestionRecovery sentTime congestionRecoveryStartTime) $ do
        now <- getTimeMillisecond
        minWindow <- kMinimumWindow conn
        -- A packet can be sent to speed up loss recovery.
        atomically $ modifyTVar' recoveryCC $ \cc@CC{congestionWindow,bytesAcked} ->
            let window0 = kLossReductionFactor congestionWindow
                window = max window0 minWindow
                acked = kLossReductionFactor bytesAcked
            in cc {
                congestionRecoveryStartTime = Just now
              , congestionWindow = window
              , ssthresh = window
              , bytesAcked = acked
              }
        -- maybeSendOnePacket conn -- fixme
        readTVarIO recoveryCC >>= qlogMetricsUpdated conn

-- Sec 7.8. Persistent Congestion
inPersistentCongestion :: Connection -> Seq SentPacket -> SentPacket -> IO Bool
inPersistentCongestion Connection{..} lostPackets' lstPkt =
    case Seq.viewl lostPackets' of
      EmptyL -> return False
      fstPkt :< _ -> do
          rtt <- readIORef recoveryRTT
          -- https://github.com/quicwg/base-drafts/pull/3290#discussion_r355089680
          -- congestion_period <= largest_lost_packet.time_sent - earliest_lost_packet.time_sent
          let pto = calcPTO rtt Nothing
              Milliseconds congestionPeriod = kPersistentCongestionThreshold pto
              threshold = microSecondsToUnixDiffTime congestionPeriod
              beg = spTimeSent fstPkt
              end = spTimeSent lstPkt
              duration = end `diffUnixTime ` beg
          return (duration >= threshold)

decreaseCC :: Connection -> Seq SentPacket -> IO ()
decreaseCC conn@Connection{..} packets = do
    let sentBytes = sum (spSentBytes <$> packets)
        num = sum (countAckEli <$> packets)
    atomically $ modifyTVar' recoveryCC $ \cc ->
      cc {
        bytesInFlight = bytesInFlight cc - sentBytes
      , numOfAckEliciting = numOfAckEliciting cc - num
      }
    readTVarIO recoveryCC >>= qlogMetricsUpdated conn

onPacketsLost :: Connection -> Seq SentPacket -> IO ()
onPacketsLost conn@Connection{..} lostPackets = case Seq.viewr lostPackets of
  EmptyR -> return ()
  lostPackets' :> lastPkt -> do
    -- Remove lost packets from bytesInFlight.
    decreaseCC conn lostPackets
    onNewCongestionEvent conn $ spTimeSent lastPkt
    mapM_ (qlogPacketLost conn) lostPackets

    -- Collapse congestion window if persistent congestion
    persistent <- inPersistentCongestion conn lostPackets' lastPkt
    when persistent $ do
        minWindow <- kMinimumWindow conn
        atomically $ modifyTVar' recoveryCC $ \cc ->
          cc {
            congestionWindow = minWindow
          , bytesAcked = 0
          }
        readTVarIO recoveryCC >>= qlogMetricsUpdated conn

retransmit :: Connection -> Seq SentPacket -> IO ()
retransmit conn lostPackets =
    mapM_ put $ Seq.filter (spAckEliciting . spSentPacketI) lostPackets
  where
    put spkt = putOutput conn $ OutRetrans $ spPlainPacket $ spSentPacketI spkt

onPacketNumberSpaceDiscarded :: Connection -> EncryptionLevel -> IO ()
onPacketNumberSpaceDiscarded conn@Connection{..} lvl = do
    -- Remove any unacknowledged packets from flight.
    clearedPackets <- releaseByClear conn lvl
    decreaseCC conn clearedPackets
    -- Reset the loss detection and PTO timer
    writeIORef (lossDetection ! lvl) initialLossDetection
    atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }
    readIORef recoveryRTT >>= qlogMetricsUpdated conn
    setLossDetectionTimer conn

----------------------------------------------------------------
----------------------------------------------------------------

resender :: Connection -> IO ()
resender conn@Connection{..} = forever $ do
    atomically $ do
        lostPackets <- readTVar lostCandidates
        check (lostPackets /= emptySentPackets)
    delay $ Microseconds 10000 -- fixme
    packets0 <- atomically $ do
        SentPackets pkts <- readTVar lostCandidates
        writeTVar lostCandidates emptySentPackets
        return pkts
    when (packets0 /= Seq.empty) $ do
        let packets = Seq.sort packets0
        onPacketsLost conn packets
        retransmit conn packets

appendLostCandidates :: Connection -> Seq SentPacket -> IO ()
appendLostCandidates Connection{..} lostPackets = atomically $ do
    SentPackets old <- readTVar lostCandidates
    let new = old >< lostPackets
    writeTVar lostCandidates $ SentPackets new

releaseLostCandidates :: Connection -> EncryptionLevel -> (SentPacket -> Bool) -> IO (Seq SentPacket)
releaseLostCandidates conn@Connection{..} lvl predicate = do
    packets <- atomically $ do
        SentPackets db <- readTVar lostCandidates
        let (pkts, db') = Seq.partition predicate db
        writeTVar lostCandidates $ SentPackets db'
        return pkts
    removePacketNumbers conn lvl packets
    return packets

----------------------------------------------------------------
----------------------------------------------------------------

releaseByPredicate :: Connection -> EncryptionLevel -> (SentPacket -> Bool) -> IO (Seq SentPacket)
releaseByPredicate conn@Connection{..} lvl predicate = do
    packets <- atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
       let (pkts, db') = Seq.partition predicate db
       in (SentPackets db', pkts)
    removePacketNumbers conn lvl packets
    return $ packets

removePacketNumbers :: Foldable t => Connection -> EncryptionLevel -> t SentPacket -> IO ()
removePacketNumbers conn lvl packets = mapM_ reduce packets
  where
    reduce x = reducePeerPacketNumbers conn lvl ppns
      where
        ppns = spPeerPacketNumbers $ spSentPacketI x

----------------------------------------------------------------

releaseByClear :: Connection -> EncryptionLevel -> IO (Seq SentPacket)
releaseByClear conn@Connection{..} lvl = do
    clearPeerPacketNumbers conn lvl
    atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
        (emptySentPackets, db)

----------------------------------------------------------------

releaseByRetry :: Connection -> IO (Seq PlainPacket)
releaseByRetry conn@Connection{..} = do
    packets <- releaseByClear conn InitialLevel
    decreaseCC conn packets
    writeIORef (lossDetection ! InitialLevel) initialLossDetection
    atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }
    readIORef recoveryRTT >>= qlogMetricsUpdated conn
    return (spPlainPacket . spSentPacketI <$> packets)

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

----------------------------------------------------------------

takePingSTM :: Connection -> STM EncryptionLevel
takePingSTM Connection{..} = do
    mx <- readTVar ptoPing
    check $ isJust mx
    writeTVar ptoPing Nothing
    return $ fromJust mx

checkWindowOpenSTM :: Connection -> Int -> STM ()
checkWindowOpenSTM Connection{..} siz = do
    CC{..} <- readTVar recoveryCC
    check (siz <= congestionWindow - bytesInFlight)

setInitialCongestionWindow :: Connection -> Int -> IO ()
setInitialCongestionWindow conn@Connection{..} pktSiz = do
    atomically $ do modifyTVar' recoveryCC $ \cc -> cc {
        congestionWindow = kInitialWindow pktSiz
      }
    readTVarIO recoveryCC >>= qlogMetricsUpdated conn
