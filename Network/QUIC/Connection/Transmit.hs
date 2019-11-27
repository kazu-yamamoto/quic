{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Transmit (
    getPacketNumber
  , getPNs
  , addPNs
  , clearPNs
  , nullPNs
  , fromPNs
  , removeAcks
  , keepOutput
  , releaseOutput
  , updateOutput
  , MilliSeconds(..)
  ) where

import Data.Hourglass
import Data.IORef
import qualified Data.IntPSQ as PSQ
import Data.Set (Set)
import qualified Data.Set as Set
import System.Hourglass

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------
-- My packet numbers

getPacketNumber :: Connection -> IO PacketNumber
getPacketNumber Connection{..} = atomicModifyIORef' packetNumber inc
  where
    inc pn = (pn + 1, pn)

----------------------------------------------------------------
-- Peer's packet numbers

getPNs :: Connection -> EncryptionLevel -> IO (Set PacketNumber)
getPNs conn lvl = readIORef ref
  where
    ref = getPacketNumbers conn lvl

addPNs :: Connection -> EncryptionLevel -> PacketNumber -> IO ()
addPNs conn lvl p = atomicModifyIORef' ref add
  where
    ref = getPacketNumbers conn lvl
    add pns = (Set.insert p pns, ())

clearPNs :: Connection -> EncryptionLevel -> IO ()
clearPNs conn lvl = atomicModifyIORef' ref clear
  where
    ref = getPacketNumbers conn lvl
    clear _ = (Set.empty, ())

updatePNs :: Connection -> EncryptionLevel -> Set PacketNumber -> IO ()
updatePNs conn lvl pns = atomicModifyIORef' ref update
  where
    ref = getPacketNumbers conn lvl
    update pns0 = (pns0 Set.\\ pns, ())

----------------------------------------------------------------

getPacketNumbers :: Connection -> EncryptionLevel -> IORef (Set PacketNumber)
getPacketNumbers conn InitialLevel   = iniPacketNumbers conn
getPacketNumbers conn RTT0Level      = appPacketNumbers conn
getPacketNumbers conn HandshakeLevel = hndPacketNumbers conn
getPacketNumbers conn RTT1Level      = appPacketNumbers conn

----------------------------------------------------------------

removeAcks :: Connection -> Retrans -> IO ()
removeAcks conn (Retrans _ lvl pns) = updatePNs conn lvl pns

nullPNs :: Set PacketNumber -> Bool
nullPNs = Set.null

fromPNs :: Set PacketNumber -> [PacketNumber]
fromPNs = Set.toDescList

----------------------------------------------------------------

keepOutput :: Connection -> PacketNumber -> Output -> EncryptionLevel -> Set PacketNumber -> IO ()
keepOutput Connection{..} pn out lvl pns = do
    tm <- timeCurrentP
    atomicModifyIORef' retransQ (add tm)
  where
    pn' = fromIntegral pn
    ent = Retrans out lvl pns
    add tm psq = (PSQ.insert pn' tm ent psq, ())

releaseOutput :: Connection -> PacketNumber -> IO (Maybe Retrans)
releaseOutput Connection{..} pn = do
    atomicModifyIORef' retransQ del
  where
    pn' = fromIntegral pn
    del psq = (PSQ.delete pn' psq, snd <$> PSQ.lookup pn' psq)

----------------------------------------------------------------

newtype MilliSeconds = MilliSeconds Int64 deriving (Eq, Show)

timeDel :: ElapsedP -> MilliSeconds -> ElapsedP
timeDel (ElapsedP sec nano) milli
  | nano' >= sec1 = ElapsedP sec (nano' - sec1)
  | otherwise     = ElapsedP (sec - 1) nano'
  where
    milliToNano (MilliSeconds n) = NanoSeconds (n * 1000000)
    sec1 = 1000000000
    nano' = nano + sec1 - milliToNano milli

updateOutput :: Connection -> MilliSeconds -> IO [Output]
updateOutput Connection{..} milli = do
    tm <- timeCurrentP
    let tm' = tm `timeDel` milli
    atomicModifyIORef' retransQ (split tm')
  where
    split x psq = (psq', map getOutput rets)
      where
        (rets, psq') = PSQ.atMostView x psq
    getOutput (_,_,Retrans x _ _) = x

----------------------------------------------------------------
