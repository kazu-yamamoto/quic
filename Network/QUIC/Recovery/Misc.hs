{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Network.QUIC.Recovery.Misc (
    getPktNumPersistent
  , setPktNumPersistent
  , setSpeedingUp
  , getSpeedingUp
  , getPacketNumberSpaceDiscarded
  , getAndSetPacketNumberSpaceDiscarded
  , setMaxAckDaley
  ) where

import Data.IORef

import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Recovery.Types
import Network.QUIC.Types

----------------------------------------------------------------
-- Packet number for 1st RTT sample

getPktNumPersistent :: LDCC -> IO PacketNumber
getPktNumPersistent LDCC{..} = readIORef pktNumPersistent

setPktNumPersistent :: LDCC -> IO ()
setPktNumPersistent ldcc@LDCC{..} =
    getPacketNumber ldcc >>= writeIORef pktNumPersistent

----------------------------------------------------------------

setSpeedingUp :: LDCC -> IO ()
setSpeedingUp LDCC{..} = writeIORef speedingUp True

getSpeedingUp :: LDCC -> IO Bool
getSpeedingUp LDCC{..} = readIORef speedingUp

----------------------------------------------------------------

getPacketNumberSpaceDiscarded :: LDCC -> EncryptionLevel -> IO Bool
getPacketNumberSpaceDiscarded LDCC{..} lvl =
    readIORef (spaceDiscarded ! lvl)

getAndSetPacketNumberSpaceDiscarded :: LDCC -> EncryptionLevel -> IO Bool
getAndSetPacketNumberSpaceDiscarded LDCC{..} lvl =
    atomicModifyIORef' (spaceDiscarded ! lvl) (True,)

----------------------------------------------------------------

setMaxAckDaley :: LDCC -> Microseconds -> IO ()
setMaxAckDaley LDCC{..} delay0 =
    atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { maxAckDelay1RTT = delay0 }
