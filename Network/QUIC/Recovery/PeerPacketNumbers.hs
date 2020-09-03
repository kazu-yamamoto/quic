{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Recovery.PeerPacketNumbers (
    getPeerPacketNumbers
  , addPeerPacketNumbers
  , delPeerPacketNumbers
  , clearPeerPacketNumbers
  , reducePeerPacketNumbers
  , setPreviousRTT1PPNs
  , getPreviousRTT1PPNs
  , nullPeerPacketNumbers
  , fromPeerPacketNumbers
  ) where

import qualified Data.Set as Set

import Network.QUIC.Imports hiding (range)
import Network.QUIC.Recovery.Types
import Network.QUIC.Types

----------------------------------------------------------------
-- Peer's packet numbers

{-# INLINE getPeerPacketNumbers #-}
getPeerPacketNumbers :: LDCC -> EncryptionLevel -> IO PeerPacketNumbers
getPeerPacketNumbers LDCC{..} lvl = get <$> readIORef peerPacketNumbers
  where
    get (PeerPacketNumbers pns)  = PeerPacketNumbers . Set.map (convert lvl) . Set.filter (range lvl) $ pns

{-# INLINE addPeerPacketNumbers #-}
addPeerPacketNumbers :: LDCC -> EncryptionLevel -> PacketNumber -> IO ()
addPeerPacketNumbers LDCC{..} lvl pn = atomicModifyIORef'' peerPacketNumbers add
  where
    add (PeerPacketNumbers pns) = PeerPacketNumbers $ Set.insert (convert lvl pn) pns

{-# INLINE delPeerPacketNumbers #-}
delPeerPacketNumbers :: LDCC -> EncryptionLevel -> PacketNumber -> IO ()
delPeerPacketNumbers LDCC{..} lvl pn = atomicModifyIORef'' peerPacketNumbers del
  where
    del (PeerPacketNumbers pns) = PeerPacketNumbers $ Set.delete (convert lvl pn) pns

{-# INLINE clearPeerPacketNumbers #-}
clearPeerPacketNumbers :: LDCC -> EncryptionLevel -> IO ()
clearPeerPacketNumbers LDCC{..} lvl = atomicModifyIORef'' peerPacketNumbers clear
  where
    clear (PeerPacketNumbers pns) = PeerPacketNumbers $ Set.filter (not . range lvl) pns

{-# INLINE reducePeerPacketNumbers #-}
reducePeerPacketNumbers :: LDCC -> EncryptionLevel -> PeerPacketNumbers -> IO ()
reducePeerPacketNumbers LDCC{..} lvl (PeerPacketNumbers pns) = atomicModifyIORef'' peerPacketNumbers reduce
  where
    pns' = Set.map (convert lvl) pns
    reduce (PeerPacketNumbers pns0) = PeerPacketNumbers (pns0 Set.\\ pns')

{-# INLINE setPreviousRTT1PPNs #-}
setPreviousRTT1PPNs :: LDCC -> PeerPacketNumbers -> IO ()
setPreviousRTT1PPNs LDCC{..} ppns = writeIORef previousRTT1PPNs ppns

{-# INLINE getPreviousRTT1PPNs #-}
getPreviousRTT1PPNs :: LDCC -> IO PeerPacketNumbers
getPreviousRTT1PPNs LDCC{..} = readIORef previousRTT1PPNs

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

{-# INLINE nullPeerPacketNumbers #-}
nullPeerPacketNumbers :: PeerPacketNumbers -> Bool
nullPeerPacketNumbers (PeerPacketNumbers pns) = Set.null pns

{-# INLINE fromPeerPacketNumbers #-}
fromPeerPacketNumbers :: PeerPacketNumbers -> [PacketNumber]
fromPeerPacketNumbers (PeerPacketNumbers pns) = Set.toDescList pns
