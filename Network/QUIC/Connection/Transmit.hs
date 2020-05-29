{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Transmit (
    keepPlainPacket
  , releaseByRetry
  , releaseByAcks
  , releaseByTimeout
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
    w1 = unsafeShiftL (w0 .&. 0x5555) 1 .|. (unsafeShiftR w0 1 .&. 0x5555)
    w2 = unsafeShiftL (w1 .&. 0x3333) 2 .|. (unsafeShiftR w1 2 .&. 0x3333)
    w3 = unsafeShiftL (w2 .&. 0x0f0f) 4 .|. (unsafeShiftR w2 4 .&. 0x0f0f)
    w4 = unsafeShiftL (w3 .&. 0x00ff) 8 .|. (unsafeShiftR w3 8 .&. 0x00ff)

toKey :: PacketNumber -> Int
toKey = fromIntegral . reverseBits . fromIntegral

third :: (a, b, c) -> c
third (_,_,x) = x

----------------------------------------------------------------

keepPlainPacket :: Connection -> PacketNumber -> EncryptionLevel -> PlainPacket -> PeerPacketNumbers -> IO ()
keepPlainPacket Connection{..} pn lvl out ppns = do
    tm <- timeCurrentP
    let ent = Retrans pn lvl out ppns
        key = toKey pn
    atomicModifyIORef' retransDB $ ins key tm ent
  where
    ins key tm ent (RetransDB db) = (RetransDB $ PSQ.insert key tm ent db, ())

----------------------------------------------------------------

releaseByRetry :: Connection -> IO [PlainPacket]
releaseByRetry Connection{..} = atomicModifyIORef' retransDB rm
  where
    rm (RetransDB db) = (emptyRetransDB, getAll db)
    getAll = map retransPlainPacket
           . sortBy (compare `on` retransPacketNumber)
           . map third
           . PSQ.toList

----------------------------------------------------------------

releaseByAcks :: Connection -> [PacketNumber] -> IO ()
releaseByAcks conn@Connection{..} pns0 = do
    msmallest <- getSmallest <$> readIORef retransDB
    let pns = case msmallest of
          Nothing       -> pns0
          Just smallest -> dropWhile (< smallest) pns0
    mapM_ (releaseByAck conn) pns
  where
    getSmallest (RetransDB db) = case PSQ.findMin db of
      Just x  -> Just $ retransPacketNumber $ third x
      Nothing -> Nothing

releaseByAck :: Connection -> PacketNumber -> IO ()
releaseByAck conn@Connection{..} pn = do
    mx <- atomicModifyIORef' retransDB get
    case mx of
      Nothing -> return ()
      Just x  -> updatePeerPacketNumbers conn (retransLevel x) (retransACKs x)
  where
    key = toKey pn
    get (RetransDB db) = (RetransDB $ PSQ.delete key db
                         ,snd <$> PSQ.lookup key db)

----------------------------------------------------------------

releaseByTimeout :: Connection -> MilliSeconds -> IO [PlainPacket]
releaseByTimeout Connection{..} milli = do
    tm <- (`timeDel` milli) <$> timeCurrentP
    atomicModifyIORef' retransDB $ split tm
  where
    split tm (RetransDB db) = let (xs, db') = PSQ.atMostView tm db
                              in (RetransDB db', map (retransPlainPacket . third) xs)

newtype MilliSeconds = MilliSeconds Int64 deriving (Eq, Show)

timeDel :: ElapsedP -> MilliSeconds -> ElapsedP
timeDel (ElapsedP sec nano) milli
  | nano' >= sec1 = ElapsedP sec (nano' - sec1)
  | otherwise     = ElapsedP (sec - 1) nano'
  where
    milliToNano (MilliSeconds n) = NanoSeconds (n * 1000000)
    sec1 = 1000000000
    nano' = nano + sec1 - milliToNano milli

----------------------------------------------------------------
