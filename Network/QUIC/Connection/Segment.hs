{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Segment (
    getPacketNumber
  , getPNs
  , addPNs
  , nullPNs
  , fromPNs
  , clearAcks
  , keepSegment
  , releaseSegment
  ) where

import Data.IORef
import qualified Data.IntPSQ as PSQ
import Data.Set (Set)
import qualified Data.Set as Set
import System.Hourglass

import Network.QUIC.Connection.Types
import Network.QUIC.Transport.Types

----------------------------------------------------------------
-- My packet numbers

getPacketNumber :: Connection -> IO PacketNumber
getPacketNumber Connection{..} = atomicModifyIORef' packetNumber inc
  where
    inc pn = (pn + 1, pn)

----------------------------------------------------------------
-- Peer's packet numbers

getPNs :: Connection -> PacketType -> IO (Set PacketNumber)
getPNs conn pt = readIORef ref
  where
    ref = getPacketNumbers conn pt

addPNs :: Connection -> PacketType -> PacketNumber -> IO ()
addPNs conn pt p = atomicModifyIORef' ref add
  where
    ref = getPacketNumbers conn pt
    add pns = (Set.insert p pns, ())


updatePNs :: Connection -> PacketType -> Set PacketNumber -> IO ()
updatePNs conn pt pns = atomicModifyIORef' ref update
  where
    ref = getPacketNumbers conn pt
    update pns0 = (pns0 Set.\\ pns, ())

----------------------------------------------------------------

getPacketNumbers :: Connection -> PacketType -> IORef (Set PacketNumber)
getPacketNumbers conn Initial   = iniPacketNumbers conn
getPacketNumbers conn Handshake = hndPacketNumbers conn
getPacketNumbers conn Short     = appPacketNumbers conn
getPacketNumbers _   _          = error "getPacketNumbers"

----------------------------------------------------------------

clearAcks :: Connection -> Retrans -> IO ()
clearAcks conn (Retrans _ pt pns) = updatePNs conn pt pns

nullPNs :: Set PacketNumber -> Bool
nullPNs = Set.null

fromPNs :: Set PacketNumber -> [PacketNumber]
fromPNs = Set.toDescList

----------------------------------------------------------------

keepSegment :: Connection -> PacketNumber -> Segment -> PacketType -> Set PacketNumber -> IO ()
keepSegment Connection{..} pn seg pt pns = do
    tm <- timeCurrentP
    atomicModifyIORef' retransQ (add tm)
  where
    pn' = fromIntegral pn
    ent = Retrans seg pt pns
    add tm psq = (PSQ.insert pn' tm ent psq, ())

releaseSegment :: Connection -> PacketNumber -> IO (Maybe Retrans)
releaseSegment Connection{..} pn = do
    atomicModifyIORef' retransQ del
  where
    pn' = fromIntegral pn
    del psq = (PSQ.delete pn' psq, snd <$> PSQ.lookup pn' psq)
