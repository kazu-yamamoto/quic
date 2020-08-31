{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Recovery.Detect (
    releaseByPredicate
  , detectAndRemoveLostPackets
  , removePacketNumbers
  ) where

import Data.Sequence (Seq, ViewL(..))
import qualified Data.Sequence as Seq

import Network.QUIC.Imports
import Network.QUIC.Qlog
import Network.QUIC.Recovery.Constants
import Network.QUIC.Recovery.PeerPacketNumbers
import Network.QUIC.Recovery.Types
import Network.QUIC.Types

releaseByPredicate :: LDCC -> EncryptionLevel -> (SentPacket -> Bool) -> IO (Seq SentPacket)
releaseByPredicate ldcc@LDCC{..} lvl predicate = do
    packets <- atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
       let (pkts, db') = Seq.partition predicate db
       in (SentPackets db', pkts)
    removePacketNumbers ldcc lvl packets
    return packets

detectAndRemoveLostPackets :: LDCC -> EncryptionLevel -> IO (Seq SentPacket)
detectAndRemoveLostPackets ldcc@LDCC{..} lvl = do
    lae <- timeOfLastAckElicitingPacket <$> readIORef (lossDetection ! lvl)
    when (lae == timeMicrosecond0) $
        qlogDebug ldcc $ Debug "detectAndRemoveLostPackets: timeOfLastAckElicitingPacket: 0"
    atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
          lossTime = Nothing
        }
    RTT{..} <- readIORef recoveryRTT
    LossDetection{..} <- readIORef (lossDetection ! lvl)
    when (largestAckedPacket == -1) $
        qlogDebug ldcc $ Debug "detectAndRemoveLostPackets: largestAckedPacket: -1"
    -- Sec 6.1.2. Time Threshold
    -- max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity)
    let lossDelay0 = kTimeThreshold $ max latestRTT smoothedRTT
    let lossDelay = max lossDelay0 kGranularity

    tm <- getPastTimeMicrosecond lossDelay
    let predicate ent = (spPacketNumber ent <= largestAckedPacket - kPacketThreshold)
                     || (spPacketNumber ent <= largestAckedPacket && spTimeSent ent <= tm)
    lostPackets <- releaseByPredicate ldcc lvl predicate

    mx <- findOldest ldcc lvl (\x -> spPacketNumber x <= largestAckedPacket)
    case mx of
      -- No gap packet. PTO turn.
      Nothing -> return ()
      -- There are gap packets which are not declared lost.
      -- Set lossTime to next.
      Just x  -> do
          let next = spTimeSent x `addMicroseconds` lossDelay
          atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
                lossTime = Just next
              }

    unless (Seq.null lostPackets) $ qlogDebug ldcc $ Debug "loss detected"
    return lostPackets

findOldest :: LDCC -> EncryptionLevel -> (SentPacket -> Bool)
           -> IO (Maybe SentPacket)
findOldest LDCC{..} lvl p = oldest <$> readIORef (sentPackets ! lvl)
  where
    oldest (SentPackets db) = case Seq.viewl $ Seq.filter p db of
      EmptyL -> Nothing
      x :< _ -> Just x

removePacketNumbers :: Foldable t => LDCC -> EncryptionLevel -> t SentPacket -> IO ()
removePacketNumbers ldcc lvl packets = mapM_ reduce packets
  where
    reduce x = reducePeerPacketNumbers ldcc lvl ppns
      where
        ppns = spPeerPacketNumbers x
