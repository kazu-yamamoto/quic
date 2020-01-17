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
import System.Hourglass

import Network.QUIC.Connection.PacketNumber
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

keepOutput :: Connection -> PacketNumber -> Output -> EncryptionLevel -> PeerPacketNumbers -> IO ()
keepOutput Connection{..} pn out lvl ppns = do
    tm <- timeCurrentP
    let pn' = fromIntegral pn
        ent = Retrans tm lvl [pn'] out ppns
    atomicModifyIORef' retransDB (\lst -> (ent:lst, ()))

releaseOutput :: Connection -> PacketNumber -> IO (Maybe Output)
releaseOutput conn pn = do
    mx <- deleteRetrans conn pn
    case mx of
      Nothing -> return Nothing
      Just x  -> return $ Just $ retransOutput x

releaseOutputRemoveAcks :: Connection -> PacketNumber -> IO ()
releaseOutputRemoveAcks conn pn = do
    mx <- deleteRetrans conn pn
    case mx of
      Nothing -> return ()
      Just x  -> updatePeerPacketNumbers conn (retransLevel x) (retransACKs x)

deleteRetrans :: Connection -> PacketNumber -> IO (Maybe Retrans)
deleteRetrans Connection{..} pn = do
    atomicModifyIORef' retransDB del
  where
    pn' = fromIntegral pn
    del []                                = ([], Nothing)
    del (x:xs)
      | pn' `elem` retransPacketNumbers x = (xs, Just x)
      | otherwise                         = x |> del xs
    a |> (as, b) = (a:as, b)

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
        split = span (\x -> retransTime x > tm')
    map retransOutput <$> atomicModifyIORef' retransDB split

----------------------------------------------------------------
