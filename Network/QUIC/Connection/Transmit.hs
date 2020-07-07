{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Transmit (
    keepPlainPacket
  , releaseByRetry
  , releaseByAcks
  , releaseByTimeout
  , releaseByTimeout'
  , findOldest
  , clearSentPackets
  , noInFlightPacket
  ) where

import Data.Function (on)
import Data.IORef
import qualified Data.IntPSQ as PSQ
import Data.List (sortBy)

import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

-- PucketNumber is increased linearly.
-- System time is also increased linearly.
-- If we use PucketNumber as key, key and priority are essentially
-- the same. This results in non-balanced PSQ.
-- It is believed that reversing bits could be a pseudo random
-- at this moment.
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
add :: PacketNumber -> TimeMillisecond -> SentPacket -> SentPackets -> SentPackets
add pn tm ent rdb = SentPackets minpn maxpn kept
  where
    minpn = min pn $ minPN rdb
    maxpn = max pn $ maxPN rdb
    key = toKey pn
    kept = PSQ.insert key tm ent $ keptPackets rdb

{-# INLINE getdel #-}
getdel :: PacketNumber -> SentPackets -> (SentPackets, Maybe SentPacket)
getdel pn rdb = case PSQ.lookup key $ keptPackets rdb of
    Nothing    -> (rdb, Nothing)
    Just (_,v) -> let kept = PSQ.delete key $ keptPackets rdb
                      newrdb = adjust rdb kept
                  in (newrdb, Just v)
  where
    key = toKey pn

{-# INLINE clear #-}
clear :: SentPackets -> SentPackets
clear rdb = case PSQ.findMin $ keptPackets rdb of
  Nothing -> rdb -- don't moidfy minPN
  Just _  -> nextEmpty rdb

{-# INLINE split #-}
split :: TimeMillisecond -> SentPackets -> (SentPackets, [(Int, TimeMillisecond, SentPacket)])
split tm rdb = case PSQ.findMin $ keptPackets rdb of
  Nothing -> (rdb, [])
  Just _  -> let (xs,kept) = PSQ.atMostView tm $ keptPackets rdb
                 newrdb = adjust rdb kept
             in (newrdb, xs)

{-# INLINE adjust #-}
adjust :: SentPackets -> PSQ.IntPSQ TimeMillisecond SentPacket -> SentPackets
adjust oldrdb newkept = case PSQ.findMin newkept of
  Nothing -> nextEmpty oldrdb
  Just x  -> let minpn = spPacketNumber $ third x
                 newrdb = oldrdb { minPN = minpn, keptPackets = newkept }
             in newrdb

{-# INLINE nextEmpty #-}
nextEmpty :: SentPackets -> SentPackets
nextEmpty rdb = emptySentPackets { minPN = minpn, maxPN = minpn }
  where
   minpn = maxPN rdb + 1

oldest :: SentPackets -> Maybe SentPacket
oldest (SentPackets _ _ psq) = third <$> PSQ.findMin psq

----------------------------------------------------------------

keepPlainPacket :: Connection -> EncryptionLevel -> PacketNumber -> PlainPacket -> PeerPacketNumbers -> Int -> IO ()
keepPlainPacket Connection{..} lvl pn ppkt ppns sentBytes = do
    tm <- getTimeMillisecond
    let ent = SentPacket {
            spPacketNumber = pn
          , spLevel        = lvl
          , spPlainPacket  = ppkt
          , spACKs         = ppns
          , spTimeSent     = tm
          , spSentBytes    = sentBytes
          }
    atomicModifyIORef' (sentPackets ! lvl) $ \rdb -> (add pn tm ent rdb, ())

----------------------------------------------------------------

releaseByRetry :: Connection -> IO [PlainPacket]
releaseByRetry Connection{..} =
    atomicModifyIORef' (sentPackets ! InitialLevel) $ \rdb -> (clear rdb, getAll (keptPackets rdb))
  where
    getAll = map spPlainPacket
           . sortBy (compare `on` spPacketNumber)
           . map third
           . PSQ.toList

----------------------------------------------------------------

releaseByAcks :: Connection -> EncryptionLevel -> AckInfo -> IO [SentPacket]
releaseByAcks conn@Connection{..} lvl ackinfo@(AckInfo largest _ _) = do
    let ref = sentPackets ! lvl
    SentPackets{..} <- readIORef ref
    if largest >= minPN then do
        let pns = fromAckInfoWithMin ackinfo minPN
        catMaybes <$> mapM (releaseByAck conn ref) pns
      else
        return []

releaseByAck :: Connection -> IORef SentPackets -> PacketNumber -> IO (Maybe SentPacket)
releaseByAck conn ref pn = do
    mx <- atomicModifyIORef' ref $ getdel pn
    case mx of
      Nothing -> return Nothing
      Just x  -> do
          reducePeerPacketNumbers conn (spLevel x) (spACKs x)
          return $ Just x

----------------------------------------------------------------

releaseByTimeout :: Connection -> EncryptionLevel -> Milliseconds -> IO [PlainPacket]
releaseByTimeout Connection{..} lvl milli = do
    tm <- getPastTimeMillisecond milli
    xs <- atomicModifyIORef' (sentPackets ! lvl) $ split tm
    return $ map (spPlainPacket . third) xs

releaseByTimeout' :: Connection -> EncryptionLevel -> Milliseconds -> IO [SentPacket]
releaseByTimeout' Connection{..} lvl milli = do
    tm <- getPastTimeMillisecond milli
    xs <- atomicModifyIORef' (sentPackets ! lvl) $ split tm
    return $ map third xs


----------------------------------------------------------------

findOldest :: Connection -> EncryptionLevel -> IO (Maybe SentPacket)
findOldest Connection{..} lvl = oldest <$> readIORef (sentPackets ! lvl)

----------------------------------------------------------------

clearSentPackets :: Connection -> EncryptionLevel -> IO [SentPacket]
clearSentPackets Connection{..} lvl = do
    atomicModifyIORef' (sentPackets ! lvl) (\db -> (emptySentPackets, map third $ PSQ.toList $ keptPackets db))

----------------------------------------------------------------

noInFlightPacket :: Connection -> EncryptionLevel -> IO Bool
noInFlightPacket Connection{..} lvl = do
    PSQ.null . keptPackets <$> readIORef (sentPackets ! lvl)
