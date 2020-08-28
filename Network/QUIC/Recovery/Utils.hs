{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NamedFieldPuns #-}

module Network.QUIC.Recovery.Utils where

import Control.Concurrent.STM
import Data.Sequence (Seq, (<|), ViewL(..))
import qualified Data.Sequence as Seq

import Network.QUIC.Imports
import Network.QUIC.Recovery.Types
import Network.QUIC.Types

----------------------------------------------------------------

sendPing :: LDCC -> EncryptionLevel -> IO ()
sendPing LDCC{..} lvl = do
    now <- getTimeMicrosecond
    atomicModifyIORef'' (lossDetection ! lvl) $ \ld -> ld {
        timeOfLastAckElicitingPacket = now
      }
    atomically $ writeTVar ptoPing $ Just lvl

----------------------------------------------------------------

mergeLostCandidates :: LDCC -> Seq SentPacket -> IO ()
mergeLostCandidates LDCC{..} lostPackets = atomically $ do
    SentPackets old <- readTVar lostCandidates
    let new = merge old lostPackets
    writeTVar lostCandidates $ SentPackets new

mergeLostCandidatesAndClear :: LDCC -> Seq SentPacket -> IO (Seq SentPacket)
mergeLostCandidatesAndClear LDCC{..} lostPackets = atomically $ do
    SentPackets old <- readTVar lostCandidates
    writeTVar lostCandidates emptySentPackets
    return $ merge old lostPackets

merge :: Seq SentPacket -> Seq SentPacket -> Seq SentPacket
merge s1 s2 = case Seq.viewl s1 of
  EmptyL   -> s2
  x :< s1' -> case Seq.viewl s2 of
    EmptyL  -> s1
    y :< s2'
      | spPacketNumber x < spPacketNumber y -> x <| merge s1' s2
      | otherwise                           -> y <| merge s1 s2'
