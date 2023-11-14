{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.PacketNumber (
    nextPacketNumber,
    setPeerPacketNumber,
    getPeerPacketNumber,
) where

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports hiding (range)
import Network.QUIC.Types

----------------------------------------------------------------
-- My packet numbers

nextPacketNumber :: Connection -> IO PacketNumber
nextPacketNumber Connection{..} = atomicModifyIORef' (packetNumber connState) inc
  where
    inc pn = (pn + 1, pn)

----------------------------------------------------------------
-- Peer's max packet number for RTT1

getPeerPacketNumber :: Connection -> IO PacketNumber
getPeerPacketNumber Connection{..} = readIORef peerPacketNumber

setPeerPacketNumber :: Connection -> PacketNumber -> IO ()
setPeerPacketNumber Connection{..} n = atomicModifyIORef'' peerPacketNumber set
  where
    set m = max m n
