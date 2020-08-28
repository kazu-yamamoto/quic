{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}

module Network.QUIC.Recovery.LossRecovery (
    onAckReceived
  , onPacketSent
  , onPacketReceived
  , onPacketNumberSpaceDiscarded
  , releaseByRetry
  , releaseOldest
  , checkWindowOpenSTM
  , takePingSTM
  , setInitialCongestionWindow
  , resender
  , speedup
  ) where

import Control.Concurrent.STM
import Data.Sequence (Seq, (<|), (|>), (><), ViewL(..), ViewR(..))
import qualified Data.Sequence as Seq
import GHC.Event hiding (new)

import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Qlog
import Network.QUIC.Recovery.Constants
import Network.QUIC.Recovery.Detect
import Network.QUIC.Recovery.Misc
import Network.QUIC.Recovery.PeerPacketNumbers
import Network.QUIC.Recovery.Persistent
import Network.QUIC.Recovery.Types
import Network.QUIC.Timeout
import Network.QUIC.Types

onPacketSent :: LDCC -> SentPacket -> IO ()
onPacketSent ldcc@LDCC{..} sentPacket = do
    let lvl0 = spEncryptionLevel sentPacket
    let lvl | lvl0 == RTT0Level = RTT1Level
            | otherwise         = lvl0
    discarded <- getPacketNumberSpaceDiscarded ldcc lvl
    unless discarded $ do
        onPacketSentCC ldcc sentPacket
        when (spAckEliciting sentPacket) $
            atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
                timeOfLastAckElicitingPacket = spTimeSent sentPacket
              }
        atomicModifyIORef'' (sentPackets ! lvl) $
            \(SentPackets db) -> SentPackets (db |> sentPacket)
        setLossDetectionTimer ldcc lvl

-- fixme
serverIsAtAntiAmplificationLimit :: Bool
serverIsAtAntiAmplificationLimit = False

onPacketReceived :: LDCC -> EncryptionLevel -> IO ()
onPacketReceived ldcc lvl = do
  -- If this datagram unblocks the server, arm the
  -- PTO timer to avoid deadlock.
  when serverIsAtAntiAmplificationLimit $ setLossDetectionTimer ldcc lvl

onAckReceived :: LDCC -> EncryptionLevel -> AckInfo -> Microseconds -> IO ()
onAckReceived ldcc@LDCC{..} lvl ackInfo@(AckInfo largestAcked _ _) ackDelay = do
    changed <- atomicModifyIORef' (lossDetection ! lvl) update
    when changed $ do
        let predicate = fromAckInfoToPred ackInfo . spPacketNumber
        releaseLostCandidates ldcc lvl predicate >>= updateCC
        releaseByPredicate    ldcc lvl predicate >>= detectLossUpdateCC
  where
    update ld@LossDetection{..} = (ld', changed)
      where
        ld' = ld { largestAckedPacket = max largestAckedPacket largestAcked
                 , previousAckInfo = ackInfo
                 }
        changed = previousAckInfo /= ackInfo
    detectLossUpdateCC newlyAckedPackets = case Seq.viewr newlyAckedPackets of
      EmptyR -> return ()
      _ :> lastPkt -> do
          -- If the largest acknowledged is newly acked and
          -- at least one ack-eliciting was newly acked, update the RTT.
          when (spPacketNumber lastPkt == largestAcked
             && any spAckEliciting newlyAckedPackets) $ do
              rtt <- getElapsedTimeMicrosecond $ spTimeSent lastPkt
              let latestRtt = max rtt kGranularity
              updateRTT ldcc lvl latestRtt ackDelay

          {- fimxe
          -- Process ECN information if present.
          if (ACK frame contains ECN information):
             ProcessECN(ack, lvl)
          -}

          lostPackets <- detectAndRemoveLostPackets ldcc lvl
          unless (null lostPackets) $ do
              mode <- ccMode <$> readTVarIO recoveryCC
              if lvl == RTT1Level && mode /= SlowStart then
                  mergeLostCandidates ldcc lostPackets
                else do
                  -- just in case
                  lostPackets' <- mergeLostCandidatesAndClear ldcc lostPackets
                  onPacketsLost ldcc lostPackets'
                  retransmit ldcc lostPackets'
          -- setLossDetectionTimer in updateCC
          updateCC newlyAckedPackets

    updateCC newlyAckedPackets
      | newlyAckedPackets == Seq.empty = return ()
      | otherwise = do
          onPacketsAcked ldcc newlyAckedPackets

          -- Sec 6.2.1. Computing PTO
          -- "The PTO backoff factor is reset when an acknowledgement is
          --  received, except in the following case. A server might
          --  take longer to respond to packets during the handshake
          --  than otherwise. To protect such a server from repeated
          --  client probes, the PTO backoff is not reset at a client
          --  that is not yet certain that the server has finished
          --  validating the client's address."
          completed <- peerCompletedAddressValidation ldcc
          when completed $ metricsUpdated ldcc $
              atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }

          setLossDetectionTimer ldcc lvl

updateRTT :: LDCC -> EncryptionLevel -> Microseconds -> Microseconds -> IO ()
updateRTT ldcc@LDCC{..} lvl latestRTT0 ackDelay0 = metricsUpdated ldcc $ do
    firstTime <- atomicModifyIORef' recoveryRTT update
    when firstTime $ do
        setPktNumPersistent ldcc
        qlogDebug ldcc $ Debug "RTT first sample"
  where
    -- don't use latestRTT, use latestRTT0 instead
    --
    -- First time:
    -- Overwriting the initial value with the first sample.
    -- Initial value was used to calculate PTO.
    --
    -- smoothed_rtt = rtt_sample
    -- rttvar = rtt_sample / 2
    update rtt@RTT{..} | latestRTT == Microseconds 0 = (rtt {
        latestRTT   = latestRTT0
      , minRTT      = latestRTT0
      , smoothedRTT = latestRTT0
      , rttvar      = latestRTT0 `unsafeShiftR` 1
      }, True)
    -- Others:
    update rtt@RTT{..} = (rtt {
        latestRTT   = latestRTT0
      , minRTT      = minRTT'
      , smoothedRTT = smoothedRTT'
      , rttvar      = rttvar'
      }, False)
      where
        -- minRTT ignores ack delay.
        minRTT' = min minRTT latestRTT0
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

getLossTimeAndSpace :: LDCC -> IO (Maybe (TimeMicrosecond,EncryptionLevel))
getLossTimeAndSpace LDCC{..} =
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

getPtoTimeAndSpace :: LDCC -> IO (Maybe (TimeMicrosecond, EncryptionLevel))
getPtoTimeAndSpace ldcc@LDCC{..} = do
    -- Arm PTO from now when there are no inflight packets.
    CC{..} <- readTVarIO recoveryCC
    if bytesInFlight <= 0 then do
        validated <- peerCompletedAddressValidation ldcc
        if validated then do
            qlogDebug ldcc $ Debug "getPtoTimeAndSpace: validated"
            return Nothing
          else do
            rtt <- readIORef recoveryRTT
            lvl <- getEncryptionLevel ldcc
            let pto = backOff (calcPTO rtt $ Just lvl) (ptoCount rtt)
            ptoTime <- getFutureTimeMicrosecond pto
            return $ Just (ptoTime, lvl)
      else do
        completed <- isConnectionEstablished ldcc
        let lvls | completed = [InitialLevel, HandshakeLevel, RTT1Level]
                 | otherwise = [InitialLevel, HandshakeLevel]
        loop lvls
  where
    loop :: [EncryptionLevel] -> IO (Maybe (TimeMicrosecond, EncryptionLevel))
    loop [] = return Nothing
    loop (l:ls) = do
        notInFlight <- noInFlightPacket ldcc l
        if notInFlight then
            loop ls
          else do
            LossDetection{..} <- readIORef (lossDetection ! l)
            if timeOfLastAckElicitingPacket == timeMicrosecond0 then
                loop ls
              else do
                  rtt <- readIORef recoveryRTT
                  let pto = backOff (calcPTO rtt $ Just l) (ptoCount rtt)
                  let ptoTime = timeOfLastAckElicitingPacket `addMicroseconds` pto
                  return $ Just (ptoTime, l)

-- Sec 6.2.1. Computing PTO
-- "That is, a client does not reset the PTO backoff factor on
--  receiving acknowledgements until it receives a HANDSHAKE_DONE
--  frame or an acknowledgement for one of its Handshake or 1-RTT
--  packets."
peerCompletedAddressValidation :: LDCC -> IO Bool
-- For servers: assume clients validate the server's address implicitly.
peerCompletedAddressValidation ldcc
  | isServer ldcc = return True
-- For clients: servers complete address validation when a protected
-- packet is received.
-- has received Handshake ACK (fixme)
-- has received 1-RTT ACK     (fixme)
-- has received HANDSHAKE_DONE
peerCompletedAddressValidation ldcc = isConnectionEstablished ldcc

cancelLossDetectionTimer :: LDCC -> IO ()
cancelLossDetectionTimer ldcc@LDCC{..} = do
    mk <- atomicModifyIORef' timerKey $ \oldkey -> (Nothing, oldkey)
    case mk of
      Nothing -> return ()
      Just k -> do
          mgr <- getSystemTimerManager
          unregisterTimeout mgr k
          oldtmi <- readIORef timerInfo
          let tmi = oldtmi { timerEvent = TimerCancelled }
          writeIORef timerInfo tmi
          qlogLossTimerUpdated ldcc tmi

updateLossDetectionTimer :: LDCC -> TimerInfo -> IO ()
updateLossDetectionTimer ldcc@LDCC{..} tmi = do
    oldtmi <- readIORef timerInfo
    when (timerTime oldtmi /= timerTime tmi) $ do
        mgr <- getSystemTimerManager
        let Left tim = timerTime tmi
        duration@(Microseconds us) <- getTimeoutInMicrosecond tim
        if us <= 0 then do
            qlogDebug ldcc $ Debug "updateLossDetectionTimer: minus"
            -- cancelLossDetectionTimer conn -- don't cancel
          else do
            key <- registerTimeout mgr us (onLossDetectionTimeout ldcc)
            mk <- atomicModifyIORef' timerKey $ \oldkey -> (Just key, oldkey)
            case mk of
              Nothing -> return ()
              Just k -> unregisterTimeout mgr k
            let newtmi = tmi { timerTime = Right duration }
            writeIORef timerInfo newtmi
            qlogLossTimerUpdated ldcc newtmi

setLossDetectionTimer :: LDCC -> EncryptionLevel -> IO ()
setLossDetectionTimer ldcc@LDCC{..} lvl0 = do
    mtl <- getLossTimeAndSpace ldcc
    case mtl of
      Just (earliestLossTime,lvl) -> do
          when (lvl0 == lvl) $ do
              -- Time threshold loss detection.
              let tmi = TimerInfo (Left earliestLossTime) lvl LossTime TimerSet
              updateLossDetectionTimer ldcc tmi
      Nothing ->
          if serverIsAtAntiAmplificationLimit then -- server is at anti-amplification limit
            -- The server's timer is not set if nothing can be sent.
              cancelLossDetectionTimer ldcc
            else do
              CC{..} <- readTVarIO recoveryCC
              validated <- peerCompletedAddressValidation ldcc
              if numOfAckEliciting <= 0 && validated then
                  -- There is nothing to detect lost, so no timer is
                  -- set. However, we only do this if the peer has
                  -- been validated, to prevent the server from being
                  -- blocked by the anti-amplification limit.
                  cancelLossDetectionTimer ldcc
                else do
                  -- Determine which PN space to arm PTO for.
                  mx <- getPtoTimeAndSpace ldcc
                  case mx of
                    Nothing -> cancelLossDetectionTimer ldcc
                    Just (ptoTime, lvl) -> do
                        when (lvl0 == lvl) $ do
                            let tmi = TimerInfo (Left ptoTime) lvl PTO TimerSet
                            updateLossDetectionTimer ldcc tmi

-- The only time the PTO is armed when there are no bytes in flight is
-- when it's a client and it's unsure if the server has completed
-- address validation.
onLossDetectionTimeout :: LDCC -> IO ()
onLossDetectionTimeout ldcc@LDCC{..} = do
    open <- isConnectionOpen ldcc
    when open $ do
        tmi <- readIORef timerInfo
        let lvl = timerLevel tmi
        discarded <- getPacketNumberSpaceDiscarded ldcc lvl
        if discarded then do
            qlogLossTimerUpdated ldcc tmi { timerEvent = TimerCancelled }
            cancelLossDetectionTimer ldcc
          else
            lossTimeOrPTO lvl tmi
  where
    lossTimeOrPTO lvl tmi = do
        qlogLossTimerUpdated ldcc tmi { timerEvent = TimerExpired }
        case timerType tmi of
          LossTime -> do
              -- Time threshold loss Detection
              lostPackets <- detectAndRemoveLostPackets ldcc lvl
              when (null lostPackets) $ qlogDebug ldcc $ Debug "onLossDetectionTimeout: null"
              lostPackets' <- mergeLostCandidatesAndClear ldcc lostPackets
              onPacketsLost ldcc lostPackets'
              retransmit ldcc lostPackets'
              setLossDetectionTimer ldcc lvl
          PTO -> do
              CC{..} <- readTVarIO recoveryCC
              if bytesInFlight > 0 then do
                  -- PTO. Send new data if available, else retransmit old data.
                  -- If neither is available, send a single PING frame.
                  sendPing ldcc lvl
                else do
                  -- Client sends an anti-deadlock packet: Initial is padded
                  -- to earn more anti-amplification credit,
                  -- a Handshake packet proves address ownership.
                  validated <- peerCompletedAddressValidation ldcc
                  when (validated) $ qlogDebug ldcc $ Debug "onLossDetectionTimeout: RTT1"
                  lvl' <- getEncryptionLevel ldcc -- fixme
                  sendPing ldcc lvl'

              metricsUpdated ldcc $
                  atomicModifyIORef'' recoveryRTT $
                      \rtt -> rtt { ptoCount = ptoCount rtt + 1 }
              setLossDetectionTimer ldcc lvl

sendPing :: LDCC -> EncryptionLevel -> IO ()
sendPing LDCC{..} lvl = do
    now <- getTimeMicrosecond
    atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
        timeOfLastAckElicitingPacket = now
      }
    atomically $ writeTVar ptoPing $ Just lvl

----------------------------------------------------------------
----------------------------------------------------------------

onPacketSentCC :: LDCC -> SentPacket -> IO ()
onPacketSentCC ldcc@LDCC{..} sentPacket = metricsUpdated ldcc $
    atomically $ modifyTVar' recoveryCC $ \cc -> cc {
        bytesInFlight = bytesInFlight cc + bytesSent
      , numOfAckEliciting = numOfAckEliciting cc + countAckEli sentPacket
      }
  where
    bytesSent = spSentBytes sentPacket

countAckEli :: SentPacket -> Int
countAckEli sentPacket
  | spAckEliciting sentPacket = 1
  | otherwise                 = 0

inCongestionRecovery :: TimeMicrosecond -> Maybe TimeMicrosecond -> Bool
inCongestionRecovery _ Nothing = False
inCongestionRecovery sentTime (Just crst) = sentTime <= crst

onPacketsAcked :: LDCC -> Seq SentPacket -> IO ()
onPacketsAcked ldcc@LDCC{..} ackedPackets = metricsUpdated ldcc $ do
    maxPktSiz <- getMaxPacketSize ldcc
    oldcc <- readTVarIO recoveryCC
    atomically $ modifyTVar' recoveryCC $ modify maxPktSiz
    newcc <- readTVarIO recoveryCC
    when (ccMode oldcc /= ccMode newcc) $
      qlogContestionStateUpdated ldcc $ ccMode newcc
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

onCongestionEvent :: LDCC -> Seq SentPacket -> Bool -> IO ()
onCongestionEvent ldcc@LDCC{..} lostPackets isRecovery = do
    persistent <- inPersistentCongestion ldcc lostPackets
    when (persistent || not isRecovery) $ do
        minWindow <- kMinimumWindow ldcc
        now <- getTimeMicrosecond
        metricsUpdated ldcc $ atomically $ modifyTVar' recoveryCC $ \cc@CC{..} ->
            let halfWindow = max minWindow $ kLossReductionFactor congestionWindow
                cwin
                  | persistent = minWindow
                  | otherwise  = halfWindow
                sst            = halfWindow
                mode
                  | cwin < sst = SlowStart -- persistent
                  | otherwise  = Recovery
            in cc {
                congestionRecoveryStartTime = Just now
              , congestionWindow = cwin
              , ssthresh         = sst
              , ccMode           = mode
              , bytesAcked       = 0
              }
        CC{ccMode} <- atomically $ readTVar recoveryCC
        qlogContestionStateUpdated ldcc ccMode

decreaseCC :: (Functor m, Foldable m) => LDCC -> m SentPacket -> IO ()
decreaseCC ldcc@LDCC{..} packets = do
    let sentBytes = sum (spSentBytes <$> packets)
        num = sum (countAckEli <$> packets)
    metricsUpdated ldcc $
        atomically $ modifyTVar' recoveryCC $ \cc ->
          cc {
            bytesInFlight = bytesInFlight cc - sentBytes
          , numOfAckEliciting = numOfAckEliciting cc - num
          }

onPacketsLost :: LDCC -> Seq SentPacket -> IO ()
onPacketsLost ldcc@LDCC{..} lostPackets = case Seq.viewr lostPackets of
  EmptyR -> return ()
  _ :> lastPkt -> do
    decreaseCC ldcc lostPackets
    isRecovery <- inCongestionRecovery (spTimeSent lastPkt) . congestionRecoveryStartTime <$> readTVarIO recoveryCC
    onCongestionEvent ldcc lostPackets isRecovery
    mapM_ (qlogPacketLost ldcc . LostPacket) lostPackets

retransmit :: LDCC -> Seq SentPacket -> IO ()
retransmit ldcc lostPackets
  | null packetsToBeResent = getEncryptionLevel ldcc >>= sendPing ldcc
  | otherwise              = mapM_ put packetsToBeResent
  where
    packetsToBeResent = Seq.filter spAckEliciting lostPackets
    put = putRetrans ldcc . spPlainPacket

onPacketNumberSpaceDiscarded :: LDCC -> EncryptionLevel -> IO ()
onPacketNumberSpaceDiscarded ldcc@LDCC{..} lvl = do
    let (lvl',label) = case lvl of
          InitialLevel -> (HandshakeLevel,"initial")
          _            -> (RTT1Level, "handshake")
    qlogDebug ldcc $ Debug (label ++ " discarded")
    discardPacketNumberSpace ldcc lvl
    -- Remove any unacknowledged packets from flight.
    clearedPackets <- releaseByClear ldcc lvl
    decreaseCC ldcc clearedPackets
    -- Reset the loss detection and PTO timer
    writeIORef (lossDetection ! lvl) initialLossDetection
    metricsUpdated ldcc $
        atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }
    setLossDetectionTimer ldcc lvl'

----------------------------------------------------------------
----------------------------------------------------------------

resender :: LDCC -> IO ()
resender ldcc@LDCC{..} = forever $ do
    atomically $ do
        lostPackets <- readTVar lostCandidates
        check (lostPackets /= emptySentPackets)
    delay $ Microseconds 10000 -- fixme
    packets <- atomically $ do
        SentPackets pkts <- readTVar lostCandidates
        writeTVar lostCandidates emptySentPackets
        return pkts
    when (packets /= Seq.empty) $ do
        onPacketsLost ldcc packets
        retransmit ldcc packets

mergeLostCandidates :: LDCC -> Seq SentPacket -> IO ()
mergeLostCandidates LDCC{..} lostPackets = atomically $ do
    SentPackets old <- readTVar lostCandidates
    let new = merge old lostPackets
    writeTVar lostCandidates $ SentPackets new

mergeLostCandidatesAndClear :: LDCC -> Seq SentPacket -> IO (Seq SentPacket)
mergeLostCandidatesAndClear LDCC{..} lostPackets = atomically $ do
    SentPackets old <- readTVar lostCandidates
    writeTVar lostCandidates emptySentPackets
    return $ merge old lostPackets

merge :: Seq SentPacket -> Seq SentPacket -> Seq SentPacket
merge s1 s2 = case Seq.viewl s1 of
  EmptyL   -> s2
  x :< s1' -> case Seq.viewl s2 of
    EmptyL  -> s1
    y :< s2'
      | spPacketNumber x < spPacketNumber y -> x <| merge s1' s2
      | otherwise                           -> y <| merge s1 s2'

releaseLostCandidates :: LDCC -> EncryptionLevel -> (SentPacket -> Bool) -> IO (Seq SentPacket)
releaseLostCandidates ldcc@LDCC{..} lvl predicate = do
    packets <- atomically $ do
        SentPackets db <- readTVar lostCandidates
        let (pkts, db') = Seq.partition predicate db
        writeTVar lostCandidates $ SentPackets db'
        return pkts
    removePacketNumbers ldcc lvl packets
    return packets

----------------------------------------------------------------

releaseByClear :: LDCC -> EncryptionLevel -> IO (Seq SentPacket)
releaseByClear ldcc@LDCC{..} lvl = do
    clearPeerPacketNumbers ldcc lvl
    atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
        (emptySentPackets, db)

----------------------------------------------------------------

releaseByRetry :: LDCC -> IO (Seq PlainPacket)
releaseByRetry ldcc@LDCC{..} = do
    packets <- releaseByClear ldcc InitialLevel
    decreaseCC ldcc packets
    writeIORef (lossDetection ! InitialLevel) initialLossDetection
    metricsUpdated ldcc $
        atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }
    return (spPlainPacket <$> packets)

----------------------------------------------------------------

speedup :: LDCC -> EncryptionLevel -> String -> IO ()
speedup ldcc@LDCC{..} lvl desc = do
    setSpeedingUp ldcc
    qlogDebug ldcc $ Debug desc
    packets <- atomicModifyIORef' (sentPackets ! lvl) $
                  \(SentPackets db) -> (emptySentPackets, db)
    -- don't clear PeerPacketNumbers.
    unless (null packets) $ do
        onPacketsLost ldcc packets
        retransmit ldcc packets
        setLossDetectionTimer ldcc lvl

----------------------------------------------------------------

-- Returning the oldest if it is ack-eliciting.
releaseOldest :: LDCC -> EncryptionLevel -> IO (Maybe SentPacket)
releaseOldest ldcc@LDCC{..} lvl = do
    mr <- atomicModifyIORef' (sentPackets ! lvl) oldest
    case mr of
      Nothing   -> return ()
      Just spkt -> do
          delPeerPacketNumbers ldcc lvl $ spPacketNumber spkt
          decreaseCC ldcc [spkt]
    return mr
  where
    oldest (SentPackets db) = case Seq.viewl db2 of
      x :< db2' -> let db' = db1 >< db2'
                   in (SentPackets db', Just x)
      _         ->    (SentPackets db, Nothing)
      where
        (db1, db2) = Seq.breakl spAckEliciting db

----------------------------------------------------------------

noInFlightPacket :: LDCC -> EncryptionLevel -> IO Bool
noInFlightPacket LDCC{..} lvl = do
    SentPackets db <- readIORef (sentPackets ! lvl)
    return $ Seq.null db

----------------------------------------------------------------

takePingSTM :: LDCC -> STM EncryptionLevel
takePingSTM LDCC{..} = do
    mx <- readTVar ptoPing
    check $ isJust mx
    writeTVar ptoPing Nothing
    return $ fromJust mx

checkWindowOpenSTM :: LDCC -> Int -> STM ()
checkWindowOpenSTM LDCC{..} siz = do
    CC{..} <- readTVar recoveryCC
    check (siz <= congestionWindow - bytesInFlight)

setInitialCongestionWindow :: LDCC -> Int -> IO ()
setInitialCongestionWindow ldcc@LDCC{..} pktSiz = metricsUpdated ldcc $
    atomically $ do modifyTVar' recoveryCC $ \cc -> cc {
        congestionWindow = kInitialWindow pktSiz
      }

----------------------------------------------------------------

metricsUpdated :: LDCC -> IO () -> IO ()
metricsUpdated ldcc@LDCC{..} body = do
    rtt0 <- readIORef recoveryRTT
    cc0 <- readTVarIO recoveryCC
    body
    rtt1 <- readIORef recoveryRTT
    cc1 <- readTVarIO recoveryCC
    let diff = catMaybes [
            time "min_rtt"      (minRTT      rtt0) (minRTT      rtt1)
          , time "smoothed_rtt" (smoothedRTT rtt0) (smoothedRTT rtt1)
          , time "latest_rtt"   (latestRTT   rtt0) (latestRTT   rtt1)
          , time "rtt_variance" (rttvar      rtt0) (rttvar      rtt1)
          , numb "pto_count"    (ptoCount    rtt0) (ptoCount    rtt1)
          , numb "bytes_in_flight"   (bytesInFlight cc0) (bytesInFlight cc1)
          , numb "congestion_window" (congestionWindow cc0) (congestionWindow cc1)
          , numb "ssthresh"          (ssthresh cc0) (ssthresh cc1)
          ]
    unless (null diff) $ qlogMetricsUpdated ldcc $ MetricsDiff diff
  where
    time tag (Microseconds v0) (Microseconds v1)
      | v0 == v1  = Nothing
      | otherwise = Just (tag,v1)
    numb tag v0 v1
      | v0 == v1  = Nothing
      | otherwise = Just (tag,v1)
