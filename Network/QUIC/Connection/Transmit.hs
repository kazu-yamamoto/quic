{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Transmit (
    keepOutput
  , releaseOutput
  , releaseOutputRemoveAcks
  , getRetransmissions
  , MilliSeconds(..)
  ) where

import Data.Hourglass
import Data.IORef
import qualified Data.IntPSQ as PSQ
import System.Hourglass

import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

keepOutput :: Connection -> PacketNumber -> Output -> EncryptionLevel -> PeerPacketNumbers -> IO ()
keepOutput Connection{..} pn out lvl pns = do
    tm <- timeCurrentP
    atomicModifyIORef' retransDB (add tm)
  where
    pn' = fromIntegral pn
    ent = Retrans out lvl pns
    add tm psq = (PSQ.insert pn' tm ent psq, ())

releaseOutput :: Connection -> PacketNumber -> IO (Maybe Output)
releaseOutput conn pn = do
    mr <- getRetrans conn pn
    case mr of
      Nothing                -> return Nothing
      Just (Retrans out _ _) -> return $ Just out

releaseOutputRemoveAcks :: Connection -> PacketNumber -> IO ()
releaseOutputRemoveAcks conn pn = do
    mr <- getRetrans conn pn
    case mr of
      Nothing                  -> return ()
      Just (Retrans _ lvl pns) -> updatePNs conn lvl pns

getRetrans :: Connection -> PacketNumber -> IO (Maybe Retrans)
getRetrans Connection{..} pn = do
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
