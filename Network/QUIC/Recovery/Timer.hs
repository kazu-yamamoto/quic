{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}

module Network.QUIC.Recovery.Timer where

import Control.Concurrent.STM
import Data.Sequence (Seq, ViewR(..))
import qualified Data.Sequence as Seq
import GHC.Event hiding (new)

import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Qlog
import Network.QUIC.Recovery.Constants
import Network.QUIC.Recovery.Detect
import Network.QUIC.Recovery.Misc
import Network.QUIC.Recovery.Persistent
import Network.QUIC.Recovery.Types
import Network.QUIC.Recovery.Utils
import Network.QUIC.Types

----------------------------------------------------------------

noInFlightPacket :: LDCC -> EncryptionLevel -> IO Bool
noInFlightPacket LDCC{..} lvl = do
    SentPackets db <- readIORef (sentPackets ! lvl)
    return $ Seq.null db

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

----------------------------------------------------------------

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

----------------------------------------------------------------

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

----------------------------------------------------------------

-- fixme
serverIsAtAntiAmplificationLimit :: Bool
serverIsAtAntiAmplificationLimit = False

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

----------------------------------------------------------------

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

----------------------------------------------------------------

inCongestionRecovery :: TimeMicrosecond -> Maybe TimeMicrosecond -> Bool
inCongestionRecovery _ Nothing = False
inCongestionRecovery sentTime (Just crst) = sentTime <= crst

onPacketsLost :: LDCC -> Seq SentPacket -> IO ()
onPacketsLost ldcc@LDCC{..} lostPackets = case Seq.viewr lostPackets of
  EmptyR -> return ()
  _ :> lastPkt -> do
    decreaseCC ldcc lostPackets
    isRecovery <- inCongestionRecovery (spTimeSent lastPkt) . congestionRecoveryStartTime <$> readTVarIO recoveryCC
    onCongestionEvent ldcc lostPackets isRecovery
    mapM_ (qlogPacketLost ldcc . LostPacket) lostPackets

----------------------------------------------------------------

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

----------------------------------------------------------------

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

countAckEli :: SentPacket -> Int
countAckEli sentPacket
  | spAckEliciting sentPacket = 1
  | otherwise                 = 0

retransmit :: LDCC -> Seq SentPacket -> IO ()
retransmit ldcc lostPackets
  | null packetsToBeResent = getEncryptionLevel ldcc >>= sendPing ldcc
  | otherwise              = mapM_ put packetsToBeResent
  where
    packetsToBeResent = Seq.filter spAckEliciting lostPackets
    put = putRetrans ldcc . spPlainPacket
