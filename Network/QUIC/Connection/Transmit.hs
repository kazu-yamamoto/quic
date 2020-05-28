{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Transmit (
    keepPlainPacket
  , releaseAllPlainPackets
  , releasePlainPacketRemoveAcks
  , getRetransmissions
  , MilliSeconds(..)
  ) where

import Data.Hourglass
import Data.IORef
import System.Hourglass

import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

keepPlainPacket :: Connection -> MyPacketNumbers -> PlainPacket -> EncryptionLevel -> PeerPacketNumbers -> IO ()
keepPlainPacket Connection{..} pns out lvl ppns = do
    tm <- timeCurrentP
    let ent = Retrans tm lvl pns out ppns
    atomicModifyIORef' retransDB (\lst -> (ent:lst, ()))

releaseAllPlainPackets :: Connection -> IO [PlainPacket]
releaseAllPlainPackets Connection{..} = atomicModifyIORef' retransDB rm
  where
    rm db = ([], reverse $ map retransPlainPacket db)

releasePlainPacketRemoveAcks :: Connection -> PacketNumber -> IO ()
releasePlainPacketRemoveAcks conn pn = do
    mx <- deleteRetrans conn pn
    case mx of
      Nothing -> return ()
      Just x  -> updatePeerPacketNumbers conn (retransLevel x) (retransACKs x)

deleteRetrans :: Connection -> PacketNumber -> IO (Maybe Retrans)
deleteRetrans Connection{..} pn = do
    atomicModifyIORef' retransDB del
  where
    del []                                           = ([], Nothing)
    del (x:xs)
      | isMyPacketNumber pn (retransPacketNumbers x) = (xs, Just x)
      | otherwise                                    = x |> del xs
    a |> (as, b) = let aas = a:as in (aas, b)

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

getRetransmissions :: Connection -> MilliSeconds -> IO [(PlainPacket,MyPacketNumbers)]
getRetransmissions Connection{..} milli = do
    tm <- timeCurrentP
    let tm' = tm `timeDel` milli
        split = span (\x -> retransTime x > tm')
    map mk <$> atomicModifyIORef' retransDB split
 where
   mk x = (retransPlainPacket x, retransPacketNumbers x)

----------------------------------------------------------------
