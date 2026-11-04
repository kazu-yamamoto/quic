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
-- Peer's largest packet number, which a truncated one is decoded against

getPeerPacketNumber :: Connection -> EncryptionLevel -> IO PacketNumber
getPeerPacketNumber Connection{..} lvl = readIORef (peerPacketNumber ! lvl)

setPeerPacketNumber :: Connection -> EncryptionLevel -> PacketNumber -> IO ()
setPeerPacketNumber Connection{..} lvl n =
    atomicModifyIORef'' (peerPacketNumber ! lvl) $ max n
