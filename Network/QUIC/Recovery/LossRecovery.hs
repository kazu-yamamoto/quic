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
import Data.Sequence (Seq, (|>), (><), ViewL(..), ViewR(..))
import qualified Data.Sequence as Seq

import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Qlog
import Network.QUIC.Recovery.Constants
import Network.QUIC.Recovery.Detect
import Network.QUIC.Recovery.Misc
import Network.QUIC.Recovery.PeerPacketNumbers
import Network.QUIC.Recovery.Persistent
import Network.QUIC.Recovery.Timer
import Network.QUIC.Recovery.Types
import Network.QUIC.Recovery.Utils
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
