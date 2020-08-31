{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}

module Network.QUIC.Recovery.Release (
    releaseByRetry
  , releaseOldest
  , discard
  , onPacketSentCC
  , onPacketsLost
  , decreaseCC
  , inCongestionRecovery
  , countAckEli
  ) where

import Control.Concurrent.STM
import Data.Sequence (Seq, (><), ViewL(..), ViewR(..))
import qualified Data.Sequence as Seq

import Network.QUIC.Imports
import Network.QUIC.Recovery.Metrics
import Network.QUIC.Recovery.PeerPacketNumbers
import Network.QUIC.Recovery.Types
import Network.QUIC.Recovery.Utils
import Network.QUIC.Types

----------------------------------------------------------------

discard :: LDCC -> EncryptionLevel -> IO (Seq SentPacket)
discard ldcc@LDCC{..} lvl = do
    packets <- releaseByClear ldcc lvl
    decreaseCC ldcc packets
    writeIORef (lossDetection ! lvl) initialLossDetection
    metricsUpdated ldcc $
        atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { ptoCount = 0 }
    return packets

releaseByClear :: LDCC -> EncryptionLevel -> IO (Seq SentPacket)
releaseByClear ldcc@LDCC{..} lvl = do
    clearPeerPacketNumbers ldcc lvl
    atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
        (emptySentPackets, db)

----------------------------------------------------------------

releaseByRetry :: LDCC -> IO (Seq PlainPacket)
releaseByRetry ldcc = do
    packets <- discard ldcc InitialLevel
    return (spPlainPacket <$> packets)

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

onPacketSentCC :: LDCC -> SentPacket -> IO ()
onPacketSentCC ldcc@LDCC{..} sentPacket = metricsUpdated ldcc $
    atomically $ modifyTVar' recoveryCC $ \cc -> cc {
        bytesInFlight = bytesInFlight cc + bytesSent
      , numOfAckEliciting = numOfAckEliciting cc + countAckEli sentPacket
      }
  where
    bytesSent = spSentBytes sentPacket

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
