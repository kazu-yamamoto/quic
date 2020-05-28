{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.PacketNumber (
    setPacketNumber
  , getPacketNumber
  , setPeerPacketNumber
  , getPeerPacketNumber
  , getPeerPacketNumbers
  , addPeerPacketNumbers
  , updatePeerPacketNumbers
  , clearPeerPacketNumbers
  , nullPeerPacketNumbers
  , fromPeerPacketNumbers
  ) where

import Data.IORef
import qualified Data.Set as Set

import Network.QUIC.Connection.Types
import Network.QUIC.Types

----------------------------------------------------------------
-- My packet numbers

getPacketNumber :: Connection -> IO PacketNumber
getPacketNumber Connection{..} = atomicModifyIORef' packetNumber inc
  where
    inc pn = (pn + 1, pn)

setPacketNumber :: Connection -> PacketNumber -> IO ()
setPacketNumber Connection{..} n = writeIORef packetNumber n

----------------------------------------------------------------
-- Peer's max packet number for RTT1

getPeerPacketNumber :: Connection -> IO PacketNumber
getPeerPacketNumber Connection{..} = readIORef peerPacketNumber

setPeerPacketNumber :: Connection -> PacketNumber -> IO ()
setPeerPacketNumber Connection{..} n = modifyIORef' peerPacketNumber set
  where
    set m = max m n

----------------------------------------------------------------
-- Peer's packet numbers

getPeerPacketNumbers :: Connection -> EncryptionLevel -> IO PeerPacketNumbers
getPeerPacketNumbers Connection{..} lvl = get <$> readIORef peerPacketNumbers
  where
    get (PeerPacketNumbers pns)  = PeerPacketNumbers . Set.map (convert lvl) . Set.filter (range lvl) $ pns

addPeerPacketNumbers :: Connection -> EncryptionLevel -> PacketNumber -> IO ()
addPeerPacketNumbers Connection{..} lvl pn = atomicModifyIORef' peerPacketNumbers add
  where
    add (PeerPacketNumbers pns) = (PeerPacketNumbers (Set.insert (convert lvl pn) pns), ())

clearPeerPacketNumbers :: Connection -> EncryptionLevel -> IO ()
clearPeerPacketNumbers Connection{..} lvl = atomicModifyIORef' peerPacketNumbers clear
  where
    clear (PeerPacketNumbers pns) = (PeerPacketNumbers (Set.filter (not . range lvl) pns), ())

updatePeerPacketNumbers :: Connection -> EncryptionLevel -> PeerPacketNumbers -> IO ()
updatePeerPacketNumbers Connection{..} lvl (PeerPacketNumbers pns) = atomicModifyIORef' peerPacketNumbers update
  where
    pns' = Set.map (convert lvl) pns
    update (PeerPacketNumbers pns0) = (PeerPacketNumbers (pns0 Set.\\ pns'), ())

----------------------------------------------------------------

initialMagic, handshakeMagic :: PacketNumber
initialMagic   = -2000
handshakeMagic = -1000

convert :: EncryptionLevel -> PacketNumber -> PacketNumber
convert InitialLevel   pn = initialMagic - pn
convert RTT0Level      pn = pn
convert HandshakeLevel pn = handshakeMagic - pn
convert RTT1Level      pn = pn

range :: EncryptionLevel -> PacketNumber -> Bool
range InitialLevel   pn = pn <= initialMagic
range RTT0Level      pn = 0 <= pn
range HandshakeLevel pn = initialMagic < pn && pn <= handshakeMagic
range RTT1Level      pn = 0 <= pn

----------------------------------------------------------------

nullPeerPacketNumbers :: PeerPacketNumbers -> Bool
nullPeerPacketNumbers (PeerPacketNumbers pns) = Set.null pns

fromPeerPacketNumbers :: PeerPacketNumbers -> [PacketNumber]
fromPeerPacketNumbers (PeerPacketNumbers pns) = Set.toDescList pns
