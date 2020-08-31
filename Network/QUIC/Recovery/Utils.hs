{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Recovery.Utils (
    retransmit
  , sendPing
  , mergeLostCandidates
  , mergeLostCandidatesAndClear
  , serverIsAtAntiAmplificationLimit
  , peerCompletedAddressValidation
  , countAckEli
  , inCongestionRecovery
  ) where

import Control.Concurrent.STM
import Data.Sequence (Seq, (<|), ViewL(..))
import qualified Data.Sequence as Seq

import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Recovery.Types
import Network.QUIC.Types

----------------------------------------------------------------

retransmit :: LDCC -> Seq SentPacket -> IO ()
retransmit ldcc lostPackets
  | null packetsToBeResent = getEncryptionLevel ldcc >>= sendPing ldcc
  | otherwise              = mapM_ put packetsToBeResent
  where
    packetsToBeResent = Seq.filter spAckEliciting lostPackets
    put = putRetrans ldcc . spPlainPacket

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

----------------------------------------------------------------

-- fixme
serverIsAtAntiAmplificationLimit :: Bool
serverIsAtAntiAmplificationLimit = False

----------------------------------------------------------------

-- Sec 6.2.1. Computing PTO
-- "That is, a client does not reset the PTO backoff factor on
--  receiving acknowledgements until it receives a HANDSHAKE_DONE
--  frame or an acknowledgement for one of its Handshake or 1-RTT
--  packets."
peerCompletedAddressValidation :: LDCC -> IO Bool
-- For servers: assume clients validate the server's address implicitly.
peerCompletedAddressValidation ldcc
  | isServer ldcc = return True
-- For clients: servers complete address validation when a protected
-- packet is received.
peerCompletedAddressValidation ldcc = isConnectionEstablished ldcc

----------------------------------------------------------------

countAckEli :: SentPacket -> Int
countAckEli sentPacket
  | spAckEliciting sentPacket = 1
  | otherwise                 = 0

----------------------------------------------------------------

inCongestionRecovery :: TimeMicrosecond -> Maybe TimeMicrosecond -> Bool
inCongestionRecovery _ Nothing = False
inCongestionRecovery sentTime (Just crst) = sentTime <= crst
