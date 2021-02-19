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

import qualified Data.IntSet as IntSet

import Network.QUIC.Imports hiding (range)
import Network.QUIC.Recovery.Types
import Network.QUIC.Types

----------------------------------------------------------------
-- Peer's packet numbers

{-# INLINE getPeerPacketNumbers #-}
getPeerPacketNumbers :: LDCC -> EncryptionLevel -> IO PeerPacketNumbers
getPeerPacketNumbers LDCC{..} lvl = readIORef (peerPacketNumbers ! lvl)

{-# INLINE addPeerPacketNumbers #-}
addPeerPacketNumbers :: LDCC -> EncryptionLevel -> PacketNumber -> IO ()
addPeerPacketNumbers LDCC{..} lvl pn =
    atomicModifyIORef'' (peerPacketNumbers ! lvl) add
  where
    add (PeerPacketNumbers pns) = PeerPacketNumbers $ IntSet.insert pn pns

{-# INLINE delPeerPacketNumbers #-}
delPeerPacketNumbers :: LDCC -> EncryptionLevel -> PacketNumber -> IO ()
delPeerPacketNumbers LDCC{..} lvl pn =
    atomicModifyIORef'' (peerPacketNumbers ! lvl) del
  where
    del (PeerPacketNumbers pns) = PeerPacketNumbers $ IntSet.delete pn pns

{-# INLINE clearPeerPacketNumbers #-}
clearPeerPacketNumbers :: LDCC -> EncryptionLevel -> IO ()
clearPeerPacketNumbers LDCC{..} lvl =
    atomicModifyIORef'' (peerPacketNumbers ! lvl) $ \_ -> emptyPeerPacketNumbers

{-# INLINE reducePeerPacketNumbers #-}
reducePeerPacketNumbers :: LDCC -> EncryptionLevel -> PeerPacketNumbers -> IO ()
reducePeerPacketNumbers LDCC{..} lvl (PeerPacketNumbers pns) =
    atomicModifyIORef'' (peerPacketNumbers ! lvl) reduce
  where
    reduce (PeerPacketNumbers pns0) = PeerPacketNumbers (pns0 IntSet.\\ pns)

{-# INLINE setPreviousRTT1PPNs #-}
setPreviousRTT1PPNs :: LDCC -> PeerPacketNumbers -> IO ()
setPreviousRTT1PPNs LDCC{..} ppns = writeIORef previousRTT1PPNs ppns

{-# INLINE getPreviousRTT1PPNs #-}
getPreviousRTT1PPNs :: LDCC -> IO PeerPacketNumbers
getPreviousRTT1PPNs LDCC{..} = readIORef previousRTT1PPNs

----------------------------------------------------------------

{-# INLINE nullPeerPacketNumbers #-}
nullPeerPacketNumbers :: PeerPacketNumbers -> Bool
nullPeerPacketNumbers (PeerPacketNumbers pns) = IntSet.null pns

{-# INLINE fromPeerPacketNumbers #-}
fromPeerPacketNumbers :: PeerPacketNumbers -> [PacketNumber]
fromPeerPacketNumbers (PeerPacketNumbers pns) = IntSet.toDescList pns
