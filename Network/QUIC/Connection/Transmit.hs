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

{-# INLINE add #-}
add :: PacketNumber -> ElapsedP -> Retrans -> RetransDB -> RetransDB
add pn tm ent rdb = RetransDB minpn maxpn kept
  where
    minpn = min pn $ minPN rdb
    maxpn = max pn $ maxPN rdb
    key = toKey pn
    kept = PSQ.insert key tm ent $ keptPackets rdb

{-# INLINE getdel #-}
getdel :: PacketNumber -> RetransDB -> (RetransDB, Maybe Retrans)
getdel pn rdb = case PSQ.lookup key $ keptPackets rdb of
    Nothing    -> (rdb, Nothing)
    Just (_,v) -> let kept = PSQ.delete key $ keptPackets rdb
                      newrdb = adjust rdb kept
                  in (newrdb, Just v)
  where
    key = toKey pn

{-# INLINE clear #-}
clear :: RetransDB -> RetransDB
clear rdb = case PSQ.findMin $ keptPackets rdb of
  Nothing -> rdb -- don't moidfy minPN
  Just _  -> nextEmpty rdb

{-# INLINE split #-}
split :: ElapsedP -> RetransDB -> (RetransDB, [(Int, ElapsedP, Retrans)])
split tm rdb = case PSQ.findMin $ keptPackets rdb of
  Nothing -> (rdb, [])
  Just _  -> let (xs,kept) = PSQ.atMostView tm $ keptPackets rdb
                 newrdb = adjust rdb kept
             in (newrdb, xs)

{-# INLINE adjust #-}
adjust :: RetransDB -> PSQ.IntPSQ ElapsedP Retrans -> RetransDB
adjust oldrdb newkept = case PSQ.findMin newkept of
  Nothing -> nextEmpty oldrdb
  Just x  -> let minpn = retransPacketNumber $ third x
                 newrdb = oldrdb { minPN = minpn, keptPackets = newkept }
             in newrdb

{-# INLINE nextEmpty #-}
nextEmpty :: RetransDB -> RetransDB
nextEmpty rdb = emptyRetransDB { minPN = minpn, maxPN = minpn }
  where
   minpn = maxPN rdb + 1

----------------------------------------------------------------

keepPlainPacket :: Connection -> PacketNumber -> EncryptionLevel -> PlainPacket -> PeerPacketNumbers -> IO ()
keepPlainPacket Connection{..} pn lvl out ppns = do
    tm <- timeCurrentP
    let ent = Retrans pn lvl out ppns
    atomicModifyIORef' retransDB $ \rdb -> (add pn tm ent rdb, ())

----------------------------------------------------------------

releaseByRetry :: Connection -> IO [PlainPacket]
releaseByRetry Connection{..} =
    atomicModifyIORef' retransDB $ \rdb -> (clear rdb, getAll (keptPackets rdb))
  where
    getAll = map retransPlainPacket
           . sortBy (compare `on` retransPacketNumber)
           . map third
           . PSQ.toList

----------------------------------------------------------------

releaseByAcks :: Connection -> AckInfo -> IO ()
releaseByAcks conn@Connection{..} ackinfo@(AckInfo largest _ _) = do
    RetransDB{..} <- readIORef retransDB
    when (largest >= minPN) $ do
        let pns = fromAckInfoWithMin ackinfo minPN
        mapM_ (releaseByAck conn) pns

releaseByAck :: Connection -> PacketNumber -> IO ()
releaseByAck conn@Connection{..} pn = do
    mx <- atomicModifyIORef' retransDB $ getdel pn
    case mx of
      Nothing -> return ()
      Just x  -> updatePeerPacketNumbers conn (retransLevel x) (retransACKs x)

----------------------------------------------------------------

releaseByTimeout :: Connection -> MilliSeconds -> IO [PlainPacket]
releaseByTimeout Connection{..} milli = do
    tm <- (`timeDel` milli) <$> timeCurrentP
    xs <- atomicModifyIORef' retransDB $ split tm
    return $ map (retransPlainPacket . third) xs

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
