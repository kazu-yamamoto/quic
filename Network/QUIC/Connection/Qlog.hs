{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Qlog where

import Network.QUIC.Connection.Types
import Network.QUIC.Qlog
import Network.QUIC.Types

qlogReceived :: Qlog a => Connection -> a -> IO ()
qlogReceived Connection{..} pkt = connQLog $ QReceived $ qlog pkt

qlogSent :: Qlog a => Connection -> a -> IO ()
qlogSent Connection{..} pkt = connQLog $ QSent $ qlog pkt

qlogDropped :: Qlog a => Connection -> a -> IO ()
qlogDropped Connection{..} pkt = connQLog $ QDropped $ qlog pkt

qlogRecvInitial :: Connection -> IO ()
qlogRecvInitial Connection{..} = connQLog QRecvInitial

qlogSentRetry :: Connection -> IO ()
qlogSentRetry Connection{..} = connQLog QSentRetry

qlogMetricsUpdated :: Qlog a => Connection -> a -> IO ()
qlogMetricsUpdated Connection{..} m = connQLog $ QMetricsUpdated $ qlog m

qlogPacketLost :: Connection -> SentPacket -> IO ()
qlogPacketLost Connection{..} spkt = connQLog $ QPacketLost $ qlog spkt

qlogContestionStateUpdated :: Connection -> CCMode -> IO ()
qlogContestionStateUpdated Connection{..} mode = connQLog $ QCongestionStateUpdated $ qlog mode

qlogLossTimerUpdated :: Connection -> TimerInfo -> IO ()
qlogLossTimerUpdated Connection{..} tmi = connQLog $ QLossTimerUpdated $ qlog tmi
