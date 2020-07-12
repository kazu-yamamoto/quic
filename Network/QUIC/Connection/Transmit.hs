{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Transmit (
    keepPlainPacket
  , releaseByAcks
  , releaseByPredicate
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
releaseByAcks conn lvl ackinfo = do
    let predicate = fromAckInfoToPred ackinfo . spPacketNumber
    releaseByPredicate conn lvl predicate

----------------------------------------------------------------

releaseByPredicate :: Connection -> EncryptionLevel -> (SentPacket -> Bool) -> IO (Seq SentPacket)
releaseByPredicate Connection{..} lvl predicate = do
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

findOldest :: Connection -> EncryptionLevel -> (SentPacket -> Bool)
           -> IO (Maybe SentPacket)
findOldest Connection{..} lvl p = oldest <$> readIORef (sentPackets ! lvl)
  where
    oldest (SentPackets db) = case Seq.viewl $ Seq.filter p db of
      EmptyL -> Nothing
      x :< _ -> Just x

----------------------------------------------------------------

noInFlightPacket :: Connection -> EncryptionLevel -> IO Bool
noInFlightPacket Connection{..} lvl = do
    SentPackets db <- readIORef (sentPackets ! lvl)
    return $ Seq.null db
