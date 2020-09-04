{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Network.QUIC.Recovery.Timer (
    getLossTimeAndSpace
  , getPtoTimeAndSpace
  , cancelLossDetectionTimer
  , setLossDetectionTimer
  , ldccTimer
  ) where

import Control.Concurrent.STM
import qualified Data.Sequence as Seq
import GHC.Event hiding (new)

import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Qlog
import Network.QUIC.Recovery.Detect
import Network.QUIC.Recovery.Metrics
import Network.QUIC.Recovery.Misc
import Network.QUIC.Recovery.Persistent
import Network.QUIC.Recovery.Release
import Network.QUIC.Recovery.Types
import Network.QUIC.Recovery.Utils
import Network.QUIC.Timeout
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
    mtmi <- readIORef timerInfo
    case mtmi of
      Nothing -> cancelLossDetectionTimer' ldcc
      Just tmi
        | timerLevel tmi == RTT1Level -> atomically $ writeTQueue timerQ Nothing
        | otherwise                   -> cancelLossDetectionTimer' ldcc

updateLossDetectionTimer :: LDCC -> TimerSet -> IO ()
updateLossDetectionTimer ldcc@LDCC{..} tmi = do
    mtmi <- readIORef timerInfo
    when (mtmi /= Just tmi) $ do
        if timerLevel tmi == RTT1Level then
            if timerType tmi == LossTime then do
              void $ atomically $ flushTQueue timerQ
              updateLossDetectionTimer' ldcc tmi
            else
              atomically $ writeTQueue timerQ $ Just tmi
          else
            updateLossDetectionTimer' ldcc tmi

ldccTimer :: LDCC -> IO ()
ldccTimer ldcc@LDCC{..} = forever $ do
    atomically $ do
        isEmpty <- isEmptyTQueue timerQ
        check (not isEmpty)
    delay $ Microseconds 10000
    xs <- atomically $ flushTQueue timerQ
    if null xs then
        return ()
      else do
        let x = last xs
        case x of
          Nothing  -> cancelLossDetectionTimer' ldcc
          Just tmi -> updateLossDetectionTimer' ldcc tmi

cancelLossDetectionTimer' :: LDCC -> IO ()
cancelLossDetectionTimer' ldcc@LDCC{..} = do
    mk <- atomicModifyIORef' timerKey (Nothing,)
    case mk of
      Nothing -> return ()
      Just k -> do
          mgr <- getSystemTimerManager
          unregisterTimeout mgr k
          writeIORef timerInfo Nothing
          qlogLossTimerCancelled ldcc

updateLossDetectionTimer' :: LDCC -> TimerSet -> IO ()
updateLossDetectionTimer' ldcc@LDCC{..} tmi = do
    mgr <- getSystemTimerManager
    let tim = timerTime tmi
    duration@(Microseconds us) <- getTimeoutInMicrosecond tim
    if us <= 0 then do
        qlogDebug ldcc $ Debug "updateLossDetectionTimer: minus"
        -- cancelLossDetectionTimer conn -- don't cancel
      else do
        key <- registerTimeout mgr us (onLossDetectionTimeout ldcc)
        mk <- atomicModifyIORef' timerKey (Just key,)
        case mk of
          Nothing -> return ()
          Just k -> unregisterTimeout mgr k
        writeIORef timerInfo $ Just tmi
        qlogLossTimerUpdated ldcc (tmi,duration)

----------------------------------------------------------------

setLossDetectionTimer :: LDCC -> EncryptionLevel -> IO ()
setLossDetectionTimer ldcc@LDCC{..} lvl0 = do
    setByAntiAmp ldcc False
    mtl <- getLossTimeAndSpace ldcc
    case mtl of
      Just (earliestLossTime,lvl) -> do
          when (lvl0 == lvl) $ do
              -- Time threshold loss detection.
              let tmi = TimerSet earliestLossTime lvl LossTime
              updateLossDetectionTimer ldcc tmi
      Nothing -> do
          inAntiAmp <- getInAntiAmp ldcc
          if inAntiAmp then do -- server is at anti-amplification limit
            -- The server's timer is not set if nothing can be sent.
              setByAntiAmp ldcc True
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
                            let tmi = TimerSet ptoTime lvl PTO
                            updateLossDetectionTimer ldcc tmi

----------------------------------------------------------------

-- The only time the PTO is armed when there are no bytes in flight is
-- when it's a client and it's unsure if the server has completed
-- address validation.
onLossDetectionTimeout :: LDCC -> IO ()
onLossDetectionTimeout ldcc@LDCC{..} = do
    open <- isConnectionOpen ldcc
    when open $ do
        mtmi <- readIORef timerInfo
        case mtmi of
          Nothing -> return ()
          Just tmi -> do
            let lvl = timerLevel tmi
            discarded <- getPacketNumberSpaceDiscarded ldcc lvl
            if discarded then
                cancelLossDetectionTimer ldcc
              else
                lossTimeOrPTO lvl tmi
  where
    lossTimeOrPTO lvl tmi = do
        qlogLossTimerExpired ldcc
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
                  when validated $ qlogDebug ldcc $ Debug "onLossDetectionTimeout: RTT1"
                  lvl' <- getEncryptionLevel ldcc -- fixme
                  sendPing ldcc lvl'

              metricsUpdated ldcc $
                  atomicModifyIORef'' recoveryRTT $
                      \rtt -> rtt { ptoCount = ptoCount rtt + 1 }
              setLossDetectionTimer ldcc lvl
