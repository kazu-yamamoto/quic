{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Transmit (
    keepPlainPacket
  , releaseAllPlainPackets
  , releasePlainPacketRemoveAcks
  , getRetransmissions
  , MilliSeconds(..)
  ) where

import Data.Function (on)
import Data.Hourglass
import Data.IORef
import qualified Data.IntPSQ as PSQ
import System.Hourglass

import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

reverseBits :: Word16 -> Word16
reverseBits w0 = w4
  where
    w1 = shiftL (w0 .&. 0x5555) 1 .|. (shiftR w0 1 .&. 0x5555)
    w2 = shiftL (w1 .&. 0x3333) 2 .|. (shiftR w1 2 .&. 0x3333)
    w3 = shiftL (w2 .&. 0x0f0f) 4 .|. (shiftR w2 4 .&. 0x0f0f)
    w4 = shiftL (w3 .&. 0x00ff) 8 .|. (shiftR w3 8 .&. 0x00ff)

toKey :: PacketNumber -> Int
toKey = fromIntegral . reverseBits . fromIntegral

----------------------------------------------------------------

keepPlainPacket :: Connection -> PacketNumber -> PlainPacket -> EncryptionLevel -> PeerPacketNumbers -> IO ()
keepPlainPacket Connection{..} pn out lvl ppns = do
    tm <- timeCurrentP
    let ent = Retrans pn lvl out ppns
        key = toKey pn
    atomicModifyIORef' retransDB $ ins key tm ent
  where
    ins key tm ent (RetransDB db) = (RetransDB $ PSQ.insert key tm ent db, ())

third :: (a, b, c) -> c
third (_,_,x) = x

releaseAllPlainPackets :: Connection -> IO [PlainPacket]
releaseAllPlainPackets Connection{..} = atomicModifyIORef' retransDB rm
  where
    rm (RetransDB db) = (emptyRetransDB, getAll db)
    getAll = map retransPlainPacket
           . sortBy (compare `on` retransPacketNumber)
           . map third
           . PSQ.toList

releasePlainPacketRemoveAcks :: Connection -> PacketNumber -> IO ()
releasePlainPacketRemoveAcks conn pn = do
    mx <- deleteRetrans conn pn
    case mx of
      Nothing -> return ()
      Just x  -> updatePeerPacketNumbers conn (retransLevel x) (retransACKs x)

deleteRetrans :: Connection -> PacketNumber -> IO (Maybe Retrans)
deleteRetrans Connection{..} pn =
    atomicModifyIORef' retransDB get
  where
    key = toKey pn
    get rdb@(RetransDB db) = case PSQ.findMin db of
      Just x | retransPacketNumber (third x) <= pn
          -> (RetransDB $ PSQ.delete key db, snd <$> PSQ.lookup key db)
      _   -> (rdb, Nothing)

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

getRetransmissions :: Connection -> MilliSeconds -> IO [PlainPacket]
getRetransmissions Connection{..} milli = do
    tm <- (`timeDel` milli) <$> timeCurrentP
    atomicModifyIORef' retransDB $ split tm
  where
    split tm (RetransDB db) = let (xs, db') = PSQ.atMostView tm db
                              in (RetransDB db', map (retransPlainPacket . third) xs)

----------------------------------------------------------------
