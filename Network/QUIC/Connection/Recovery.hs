{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}

module Network.QUIC.Connection.Recovery (
    onAckReceived
  , onPacketSent
  , onPacketReceived
  , onPacketNumberSpaceDiscarded
  , releaseByRetry
  , waitWindowOpen
  , setInitialCongestionWindow
  ) where

import Control.Concurrent.STM
import Data.Sequence (Seq, (|>), ViewL(..), ViewR(..))
import qualified Data.Sequence as Seq
import Data.UnixTime
import GHC.Event

import Network.QUIC.Connection.Crypto
import Network.QUIC.Connection.PacketNumber
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
kGranularity = Milliseconds 5

onPacketSent :: Connection -> SentPacket -> IO ()
onPacketSent conn@Connection{..} sentPacket = do
    let lvl0 = spEncryptionLevel $ spSentPacketI sentPacket
    let lvl | lvl0 == RTT0Level = RTT1Level
            | otherwise         = lvl0
    onPacketSentCC conn $ spSentBytes sentPacket
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

onPacketReceived :: Connection -> IO ()
onPacketReceived conn = do
  -- If this datagram unblocks the server, arm the
  -- PTO timer to avoid deadlock.
  when serverIsAtAntiAmplificationLimit $ setLossDetectionTimer conn

onAckReceived :: Connection -> EncryptionLevel -> AckInfo -> Milliseconds -> IO ()
onAckReceived conn@Connection{..} lvl ackInfo@(AckInfo largestAcked _ _) ackDelay = do
    changed <- atomicModifyIORef' (lossDetection ! lvl) update
    when changed $ releaseByAcks conn lvl ackInfo >>= process
  where
    update ld@LossDetection{..} = (ld', changed)
      where
        ld' = ld { largestAckedPacket = max largestAckedPacket largestAcked
                 , previousAckInfo = ackInfo
                 }
        changed = previousAckInfo /= ackInfo
    process newlyAckedPackets = case Seq.viewr newlyAckedPackets of
      EmptyR -> return ()
      _ :> lastPkt -> do
          -- If the largest acknowledged is newly acked and
          -- at least one ack-eliciting was newly acked, update the RTT.
          when (spPacketNumber (spSentPacketI lastPkt) == largestAcked
             && any (spAckEliciting . spSentPacketI) newlyAckedPackets) $ do
              rtt <- getElapsedTimeMillisecond $ spTimeSent lastPkt
              let latestRtt = max rtt kGranularity
              updateRTT conn lvl latestRtt ackDelay

          {- fimxe
          -- Process ECN information if present.
          if (ACK frame contains ECN information):
             ProcessECN(ack, lvl)
          -}

          lostPackets <- detectAndRemoveLostPackets conn lvl
          onPacketsLost conn lvl lostPackets
          retransmit conn lostPackets

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
          when completed $ atomicModifyIORef'' recoveryRTT $ \rtt ->
            rtt { ptoCount = 0 }

          setLossDetectionTimer conn

updateRTT :: Connection -> EncryptionLevel -> Milliseconds -> Milliseconds -> IO ()
updateRTT Connection{..} lvl latestRTT0 ackDelay0 = atomicModifyIORef'' recoveryRTT $ \rtt@RTT{..} ->
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
            ackDelay = min ackDelay0 $ getMaxAckDelay lvl maxAckDelay1RTT
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

detectAndRemoveLostPackets :: Connection -> EncryptionLevel -> IO (Seq SentPacket)
detectAndRemoveLostPackets conn@Connection{..} lvl = do
    lae <- timeOfLastAckElicitingPacket <$> readIORef (lossDetection ! lvl)
    when (lae == timeMillisecond0) $ connDebugLog "detectAndRemoveLostPackets: timeOfLastAckElicitingPacket: 0"
    atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
          lossTime = Nothing
        }
    RTT{..} <- readIORef recoveryRTT
    LossDetection{..} <- readIORef (lossDetection ! lvl)
    when (largestAckedPacket == -1) $ connDebugLog "detectAndRemoveLostPackets: largestAckedPacket: -1"
    -- Sec 6.1.2. Time Threshold
    -- max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)
    let lossDelay0 = kTimeThreshold $ max latestRTT smoothedRTT
    let lossDelay = max lossDelay0 kGranularity

    tm <- getPastTimeMillisecond lossDelay
    let predicate ent = (spPacketNumber (spSentPacketI ent) <= largestAckedPacket - kPacketThreshold)
                     || (spPacketNumber (spSentPacketI ent) <= largestAckedPacket && spTimeSent ent <= tm)
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

getMaxAckDelay :: EncryptionLevel -> Milliseconds -> Milliseconds
getMaxAckDelay lvl delay
  | lvl `elem` [InitialLevel,HandshakeLevel] = 0
  | otherwise                                = delay

-- Sec 6.2.1. Computing PTO
-- PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
calcPTO :: RTT -> EncryptionLevel -> Milliseconds
calcPTO RTT{..} lvl = smoothedRTT + max (rttvar .<<. 2) kGranularity + delay
  where
    delay = getMaxAckDelay lvl maxAckDelay1RTT

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
            let pto = backOff (calcPTO rtt lvl) (ptoCount rtt)
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
                  let pto = backOff (calcPTO rtt l) (ptoCount rtt)
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
cancelLossDetectionTimer Connection{..} = do
    mk <- atomicModifyIORef' timeoutKey $ \oldkey -> (Nothing, oldkey)
    case mk of
      Nothing -> return ()
      Just k -> do
          mgr <- getSystemTimerManager
          unregisterTimeout mgr k

updateLossDetectionTimer :: Connection -> TimeMillisecond -> IO ()
updateLossDetectionTimer conn@Connection{..} tms = do
    oldtms <- readIORef timeoutTime
    when (oldtms /= Just tms) $ do
        mgr <- getSystemTimerManager
        Microseconds us <- getTimeoutInMicrosecond tms
        if us <= 0 then do
            connDebugLog "updateLossDetectionTimer: minus"
            cancelLossDetectionTimer conn
          else do
            key <- registerTimeout mgr us (onLossDetectionTimeout conn)
            mk <- atomicModifyIORef' timeoutKey $ \oldkey -> (Just key, oldkey)
            case mk of
              Nothing -> return ()
              Just k -> unregisterTimeout mgr k
            writeIORef timeoutTime $ Just tms

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
              cancelLossDetectionTimer conn
            else do
              CC{..} <- readTVarIO recoveryCC
              validated <- peerCompletedAddressValidation conn
              if bytesInFlight <= 0 && validated then
                  -- There is nothing to detect lost, so no timer is set.
                  -- However, the client needs to arm the timer if the
                  -- server might be blocked by the anti-amplification limit.
                  cancelLossDetectionTimer conn
                else do
                  -- Determine which PN space to arm PTO for.
                  mx <- getPtoTimeAndSpace conn
                  case mx of
                    Nothing -> cancelLossDetectionTimer conn
                    Just (timeout, _) -> updateLossDetectionTimer conn timeout

-- The only time the PTO is armed when there are no bytes in flight is
-- when it's a client and it's unsure if the server has completed
-- address validation.
onLossDetectionTimeout :: Connection -> IO ()
onLossDetectionTimeout conn@Connection{..} = do
    open <- isConnectionOpen conn
    when open $ do
        mtl <- getLossTimeAndSpace conn
        case mtl of
          Just (_, lvl) -> do
              -- Time threshold loss Detection
              lostPackets <- detectAndRemoveLostPackets conn lvl
              when (null lostPackets) $ connDebugLog "onLossDetectionTimeout: null"
              onPacketsLost conn lvl lostPackets
              retransmit conn lostPackets
              setLossDetectionTimer conn
          Nothing -> do
              CC{..} <- readTVarIO recoveryCC
              if bytesInFlight > 0 then do
                  -- PTO. Send new data if available, else retransmit old data.
                  -- If neither is available, send a single PING frame.
                  mx <- getPtoTimeAndSpace conn
                  case mx of
                    Nothing -> connDebugLog "onLossDetectionTimeout: Nothing"
                    Just (_, lvl) -> do
                        now <- getTimeMillisecond
                        atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
                            timeOfLastAckElicitingPacket = now
                          }
                        putOutput conn $ OutControl lvl [Ping]
                        putOutput conn $ OutControl lvl [Ping]
                else do
                  -- Client sends an anti-deadlock packet: Initial is padded
                  -- to earn more anti-amplification credit,
                  -- a Handshake packet proves address ownership.
                  validated <- peerCompletedAddressValidation conn
                  when (validated) $ connDebugLog "onLossDetectionTimeout: RTT1"
                  lvl <- getEncryptionLevel conn
                  now <- getTimeMillisecond
                  atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
                      timeOfLastAckElicitingPacket = now
                    }
                  putOutput conn $ OutControl lvl [Ping]

              atomicModifyIORef'' recoveryRTT $ \rtt ->
                rtt { ptoCount = ptoCount rtt + 1 }
              setLossDetectionTimer conn

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

onPacketSentCC :: Connection -> Int -> IO ()
onPacketSentCC Connection{..} bytesSent = atomically $
    modifyTVar' recoveryCC $ \cc -> cc {
        bytesInFlight = bytesInFlight cc + bytesSent
      }

inCongestionRecovery :: TimeMillisecond -> Maybe TimeMillisecond -> Bool
inCongestionRecovery _ Nothing = False -- checkme
inCongestionRecovery sentTime (Just crst) = sentTime <= crst

onPacketsAcked :: Connection -> Seq SentPacket -> IO ()
onPacketsAcked Connection{..} ackedPackets = do
    maxPktSiz <- readIORef maxPacketSize
    atomically $ modifyTVar' recoveryCC $ modify maxPktSiz
  where
    modify maxPktSiz cc@CC{..} = cc {
           bytesInFlight = bytesInFlight'
         , congestionWindow = congestionWindow'
         , bytesAcked = bytesAcked'
         , ccMode = ccMode'
         }
      where
        (bytesInFlight',congestionWindow',bytesAcked',ccMode') =
              foldl' (.+) (bytesInFlight,congestionWindow,bytesAcked,ccMode) ackedPackets
        (bytes,cwin,acked,_) .+ SentPacket{..} = (bytes',cwin',acked',mode')
          where
            isRecovery = inCongestionRecovery spTimeSent congestionRecoveryStartTime
            bytes' = bytes - spSentBytes
            ackedA = acked + spSentBytes
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

-- Sec 7.8. Persistent Congestion
inPersistentCongestion :: Connection -> EncryptionLevel -> Seq SentPacket -> SentPacket -> IO Bool
inPersistentCongestion Connection{..} lvl lostPackets' lstPkt =
    case Seq.viewl lostPackets' of
      EmptyL -> return False
      fstPkt :< _ -> do
          rtt <- readIORef recoveryRTT
          -- https://github.com/quicwg/base-drafts/pull/3290#discussion_r355089680
          -- congestion_period <= largest_lost_packet.time_sent - earliest_lost_packet.time_sent
          let pto = calcPTO rtt lvl
              Milliseconds congestionPeriod = kPersistentCongestionThreshold pto
              threshold = microSecondsToUnixDiffTime congestionPeriod
              beg = spTimeSent fstPkt
              end = spTimeSent lstPkt
              duration = end `diffUnixTime ` beg
          return (duration >= threshold)

decreaseBytesInFlight :: Connection -> Seq SentPacket -> IO ()
decreaseBytesInFlight Connection{..} packets = do
    let sentBytes = sum (spSentBytes <$> packets)
    atomically $ modifyTVar' recoveryCC $ \cc ->
      cc { bytesInFlight = bytesInFlight cc - sentBytes }

onPacketsLost :: Connection -> EncryptionLevel -> Seq SentPacket -> IO ()
onPacketsLost conn@Connection{..} lvl lostPackets = case Seq.viewr lostPackets of
  EmptyR -> return ()
  lostPackets' :> lastPkt -> do
    -- Remove lost packets from bytesInFlight.
    decreaseBytesInFlight conn lostPackets
    onNewCongestionEvent conn $ spTimeSent lastPkt

    -- Collapse congestion window if persistent congestion
    persistent <- inPersistentCongestion conn lvl lostPackets' lastPkt
    when persistent $ do
        minWindow <- kMinimumWindow conn
        atomically $ modifyTVar' recoveryCC $ \cc ->
          cc {
            congestionWindow = minWindow
          , bytesAcked = 0
          }

retransmit :: Connection -> Seq SentPacket -> IO ()
retransmit conn lostPackets =
    mapM_ put $ Seq.filter (spAckEliciting . spSentPacketI) lostPackets
  where
    put spkt = putOutput conn $ OutRetrans $ spPlainPacket $ spSentPacketI spkt

onPacketNumberSpaceDiscarded :: Connection -> EncryptionLevel -> IO ()
onPacketNumberSpaceDiscarded conn@Connection{..} lvl = do
    clearPeerPacketNumbers conn lvl
    -- Remove any unacknowledged packets from flight.
    clearedPackets <- releaseByClear conn lvl
    decreaseBytesInFlight conn clearedPackets
    -- Reset the loss detection and PTO timer
    writeIORef (lossDetection ! lvl) initialLossDetection
    atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }
    setLossDetectionTimer conn

----------------------------------------------------------------
----------------------------------------------------------------

releaseByAcks :: Connection -> EncryptionLevel -> AckInfo -> IO (Seq SentPacket)
releaseByAcks conn lvl ackinfo = do
    let predicate = fromAckInfoToPred ackinfo . spPacketNumber . spSentPacketI
    releaseByPredicate conn lvl predicate

----------------------------------------------------------------

releaseByPredicate :: Connection -> EncryptionLevel -> (SentPacket -> Bool) -> IO (Seq SentPacket)
releaseByPredicate conn@Connection{..} lvl predicate = do
    packets <- atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
       let (lostPackets, db') = Seq.partition predicate db
       in (SentPackets db', lostPackets)
    mapM_ reduce packets
    return $ packets
  where
    reduce x = reducePeerPacketNumbers conn lvl ppns
      where
        ppns = spPeerPacketNumbers $ spSentPacketI x

----------------------------------------------------------------

releaseByClear :: Connection -> EncryptionLevel -> IO (Seq SentPacket)
releaseByClear Connection{..} lvl = do
    atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
        (emptySentPackets, db)

----------------------------------------------------------------

releaseByRetry :: Connection -> IO (Seq PlainPacket)
releaseByRetry conn@Connection{..} = do
    packets <- releaseByClear conn InitialLevel
    decreaseBytesInFlight conn packets
    writeIORef (lossDetection ! InitialLevel) initialLossDetection
    atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }
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

waitWindowOpen :: Connection -> Int -> IO ()
waitWindowOpen Connection{..} siz = atomically $ do
    CC{..} <- readTVar recoveryCC
    check (siz <= congestionWindow - bytesInFlight)

setInitialCongestionWindow :: Connection -> Int -> IO ()
setInitialCongestionWindow Connection{..} pktSiz = atomically $ do
    modifyTVar' recoveryCC $ \cc -> cc {
        congestionWindow = kInitialWindow pktSiz
      }
