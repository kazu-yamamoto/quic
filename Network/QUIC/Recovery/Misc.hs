{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Recovery.Misc (
    getPktNumPersistent
  , setPktNumPersistent
  , setSpeedingUp
  , getSpeedingUp
  , discardPacketNumberSpace
  , getPacketNumberSpaceDiscarded
  , setMaxAckDaley
  , setByAntiAmp
  , getByAntiAmp
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

discardPacketNumberSpace :: LDCC -> EncryptionLevel -> IO ()
discardPacketNumberSpace LDCC{..} lvl = writeArray spaceDiscarded lvl True

getPacketNumberSpaceDiscarded :: LDCC -> EncryptionLevel -> IO Bool
getPacketNumberSpaceDiscarded LDCC{..} lvl = readArray spaceDiscarded lvl

----------------------------------------------------------------

setMaxAckDaley :: LDCC -> Microseconds -> IO ()
setMaxAckDaley LDCC{..} delay0 =
    atomicModifyIORef'' recoveryRTT $ \rtt -> rtt { maxAckDelay1RTT = delay0 }

----------------------------------------------------------------

setByAntiAmp :: LDCC -> Bool -> IO ()
setByAntiAmp LDCC{..} b = writeIORef byAntiAmp b

getByAntiAmp :: LDCC -> IO Bool
getByAntiAmp LDCC{..} = readIORef byAntiAmp
