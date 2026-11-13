{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.PacketNumber (
    nextPacketNumber,
    setPeerPacketNumber,
    getPeerPacketNumber,
    recordPeerPacketNumber,
    receivedWindow,
) where

import qualified Data.IntSet as IntSet

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

----------------------------------------------------------------
-- Peer's packet numbers processed, against duplicates

-- | How far below the largest a packet number is remembered.  Older ones
--   are taken as duplicates (RFC 9000 Sec 12.3).
receivedWindow :: PacketNumber
receivedWindow = 4096

-- | Recording a packet number of the peer, 'False' if it may be a duplicate.
recordPeerPacketNumber
    :: Connection -> EncryptionLevel -> PacketNumber -> IO Bool
recordPeerPacketNumber Connection{..} lvl pn =
    atomicModifyIORef' (peerReceived ! lvl) record
  where
    record pns
        | pn `IntSet.member` pns = (pns, False)
        | otherwise = case fst <$> IntSet.maxView pns of
            Just mx
                | pn < mx - receivedWindow -> (pns, False)
                | pn < mx -> (IntSet.insert pn pns, True)
            _ -> (snd $ IntSet.split (pn - receivedWindow - 1) $ IntSet.insert pn pns, True)
