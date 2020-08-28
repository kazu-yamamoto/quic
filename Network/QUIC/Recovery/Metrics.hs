{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}

module Network.QUIC.Recovery.Metrics where

import Control.Concurrent.STM
import Data.Sequence (Seq)

import Network.QUIC.Imports
import Network.QUIC.Qlog
import Network.QUIC.Recovery.Constants
import Network.QUIC.Recovery.Misc
import Network.QUIC.Recovery.Persistent
import Network.QUIC.Recovery.Types
import Network.QUIC.Types

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
