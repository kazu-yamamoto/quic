{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Transmit (
    keepPlainPacket
  , releaseByAcks
  , releaseByTimeout
  , releaseByClear
  , releaseByRetry
  , findOldest
  , noInFlightPacket
  ) where

import Data.IORef
import Data.Sequence (Seq, (<|), ViewL(..))
import qualified Data.Sequence as Seq

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

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
    atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
      let db' = ent <| db
      in  (SentPackets db', ())

----------------------------------------------------------------

releaseByAcks :: Connection -> EncryptionLevel -> AckInfo -> IO (Seq SentPacket)
releaseByAcks Connection{..} lvl ackinfo = do
    let predicate = fromAckInfoToPred ackinfo . spPacketNumber
    atomicModifyIORef'(sentPackets ! lvl) $ \(SentPackets db) ->
        let (newlyAckedPackets, db') = Seq.partition predicate db
        in (SentPackets db', newlyAckedPackets)

----------------------------------------------------------------

releaseByTimeout :: Connection -> EncryptionLevel -> Milliseconds -> IO (Seq SentPacket)
releaseByTimeout Connection{..} lvl milli = do
    tm <- getPastTimeMillisecond milli
    let predicate ent = spTimeSent ent <= tm
    atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
       let (lostPackets, db') = Seq.partition predicate db
       in (SentPackets db', lostPackets)

----------------------------------------------------------------

releaseByClear :: Connection -> EncryptionLevel -> IO (Seq SentPacket)
releaseByClear Connection{..} lvl = do
    atomicModifyIORef' (sentPackets ! lvl) $ \(SentPackets db) ->
        (emptySentPackets, db)

----------------------------------------------------------------

releaseByRetry :: Connection -> IO (Seq PlainPacket)
releaseByRetry conn = fmap spPlainPacket <$> releaseByClear conn InitialLevel

----------------------------------------------------------------

findOldest :: Connection -> EncryptionLevel -> IO (Maybe SentPacket)
findOldest Connection{..} lvl = oldest <$> readIORef (sentPackets ! lvl)
  where
    oldest (SentPackets db) = case Seq.viewl db of
      EmptyL -> Nothing
      x :< _ -> Just x

----------------------------------------------------------------

noInFlightPacket :: Connection -> EncryptionLevel -> IO Bool
noInFlightPacket Connection{..} lvl = do
    SentPackets db <- readIORef (sentPackets ! lvl)
    return $ Seq.null db
