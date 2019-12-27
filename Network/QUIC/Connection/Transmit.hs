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
  , getRetransmissions
  , MilliSeconds(..)
  ) where

import Data.Hourglass
import Data.IORef
import qualified Data.IntPSQ as PSQ
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

removeAcks :: Connection -> Retrans -> IO ()
removeAcks conn (Retrans _ lvl pns) = updatePNs conn lvl pns

nullPNs :: PeerPacketNumbers -> Bool
nullPNs (PeerPacketNumbers pns) = Set.null pns

fromPNs :: PeerPacketNumbers -> [PacketNumber]
fromPNs (PeerPacketNumbers pns) = Set.toDescList pns

----------------------------------------------------------------

keepOutput :: Connection -> PacketNumber -> Output -> EncryptionLevel -> PeerPacketNumbers -> IO ()
keepOutput Connection{..} pn out lvl pns = do
    tm <- timeCurrentP
    atomicModifyIORef' retransDB (add tm)
  where
    pn' = fromIntegral pn
    ent = Retrans out lvl pns
    add tm psq = (PSQ.insert pn' tm ent psq, ())

releaseOutput :: Connection -> PacketNumber -> IO (Maybe Retrans)
releaseOutput Connection{..} pn = do
    atomicModifyIORef' retransDB del
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

getRetransmissions :: Connection -> MilliSeconds -> IO [Output]
getRetransmissions Connection{..} milli = do
    tm <- timeCurrentP
    let tm' = tm `timeDel` milli
    atomicModifyIORef' retransDB (split tm')
  where
    split x psq = (psq', map getOutput rets)
      where
        (rets, psq') = PSQ.atMostView x psq
    getOutput (_,_,Retrans x _ _) = x

----------------------------------------------------------------
