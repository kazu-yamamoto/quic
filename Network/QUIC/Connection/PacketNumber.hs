{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.PacketNumber (
    getPacketNumber
  , getPNs
  , addPNs
  , updatePNs
  , clearPNs
  , nullPNs
  , fromPNs
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

----------------------------------------------------------------
-- Peer's packet numbers

getPNs :: Connection -> EncryptionLevel -> IO PeerPacketNumbers
getPNs Connection{..} lvl = get <$> readIORef peerPacketNumbers
  where
    get (PeerPacketNumbers pns)  = PeerPacketNumbers . Set.map (convert lvl) . Set.filter (range lvl) $ pns

addPNs :: Connection -> EncryptionLevel -> PacketNumber -> IO ()
addPNs Connection{..} lvl pn = atomicModifyIORef' peerPacketNumbers add
  where
    add (PeerPacketNumbers pns) = (PeerPacketNumbers (Set.insert (convert lvl pn) pns), ())

clearPNs :: Connection -> EncryptionLevel -> IO ()
clearPNs Connection{..} lvl = atomicModifyIORef' peerPacketNumbers clear
  where
    clear (PeerPacketNumbers pns) = (PeerPacketNumbers (Set.filter (not . range lvl) pns), ())

updatePNs :: Connection -> EncryptionLevel -> PeerPacketNumbers -> IO ()
updatePNs Connection{..} lvl (PeerPacketNumbers pns) = atomicModifyIORef' peerPacketNumbers update
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

nullPNs :: PeerPacketNumbers -> Bool
nullPNs (PeerPacketNumbers pns) = Set.null pns

fromPNs :: PeerPacketNumbers -> [PacketNumber]
fromPNs (PeerPacketNumbers pns) = Set.toDescList pns
