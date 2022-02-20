{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Recovery.Interface (
    checkWindowOpenSTM
  , takePingSTM
  , speedup
  , resender
  ) where

import qualified Data.Sequence as Seq
import System.Log.FastLogger (LogStr)
import UnliftIO.STM

import Network.QUIC.Imports
import Network.QUIC.Qlog
import Network.QUIC.Recovery.Misc
import Network.QUIC.Recovery.Release
import Network.QUIC.Recovery.Timer
import Network.QUIC.Recovery.Types
import Network.QUIC.Recovery.Utils
import Network.QUIC.Types

checkWindowOpenSTM :: LDCC -> Int -> STM ()
checkWindowOpenSTM LDCC{..} siz = do
    CC{..} <- readTVar recoveryCC
    checkSTM (siz <= congestionWindow - bytesInFlight)

takePingSTM :: LDCC -> STM EncryptionLevel
takePingSTM LDCC{..} = do
    mx <- readTVar ptoPing
    checkSTM $ isJust mx
    writeTVar ptoPing Nothing
    return $ fromJust mx

speedup :: LDCC -> EncryptionLevel -> LogStr -> IO ()
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

resender :: LDCC -> IO ()
resender ldcc@LDCC{..} = forever $ do
    atomically $ do
        lostPackets <- readTVar lostCandidates
        checkSTM (lostPackets /= emptySentPackets)
    delay $ Microseconds 10000 -- fixme
    packets <- atomically $ do
        SentPackets pkts <- readTVar lostCandidates
        writeTVar lostCandidates emptySentPackets
        return pkts
    when (packets /= Seq.empty) $ do
        onPacketsLost ldcc packets
        retransmit ldcc packets
