{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Network.QUIC.Types.Time (
    Milliseconds(..)
  , Microseconds(..)
  , milliToMicro
  , microToMilli
  , TimeMicrosecond
  , timeMicrosecond0
  , getTimeMicrosecond
  , getElapsedTimeMicrosecond
  , getTimeoutInMicrosecond
  , getPastTimeMicrosecond
  , getFutureTimeMicrosecond
  , addMicroseconds
  ) where

import Data.UnixTime
import Foreign.C.Types (CTime(..))

import Network.QUIC.Imports

----------------------------------------------------------------

newtype Milliseconds = Milliseconds Int64 deriving (Eq, Ord, Num, Bits)
newtype Microseconds = Microseconds Int deriving (Eq, Ord, Num, Bits)

instance Show Milliseconds where
  show (Milliseconds n) = show n

instance Show Microseconds where
  show (Microseconds n) = show n

{-# INLINE milliToMicro #-}
milliToMicro :: Milliseconds -> Microseconds
milliToMicro (Milliseconds n) = Microseconds (fromIntegral n * 1000)

microToMilli :: Microseconds -> Milliseconds
microToMilli (Microseconds n) = Milliseconds (fromIntegral n `div` 1000)

----------------------------------------------------------------

type TimeMicrosecond = UnixTime

timeMicrosecond0 :: UnixTime
timeMicrosecond0 = UnixTime 0 0

----------------------------------------------------------------

getTimeMicrosecond :: IO TimeMicrosecond
getTimeMicrosecond = getUnixTime

----------------------------------------------------------------

getElapsedTimeMicrosecond :: TimeMicrosecond -> IO Microseconds
getElapsedTimeMicrosecond base = do
    c <- getTimeMicrosecond
    let UnixDiffTime (CTime s) u = c `diffUnixTime` base
        elapsed = fromIntegral (s * 1000000 + (fromIntegral u))
    return $ Microseconds elapsed

getTimeoutInMicrosecond :: TimeMicrosecond -> IO Microseconds
getTimeoutInMicrosecond tmout = do
    c <- getTimeMicrosecond
    let UnixDiffTime (CTime s) u = tmout `diffUnixTime` c
        timeout = fromIntegral s * 1000000 + fromIntegral u
    return $ Microseconds timeout

----------------------------------------------------------------

getPastTimeMicrosecond :: Microseconds -> IO TimeMicrosecond
getPastTimeMicrosecond (Microseconds us) = do
    let diff = microSecondsToUnixDiffTime $ negate us
    c <- getTimeMicrosecond
    let past = c `addUnixDiffTime` diff
    return past

getFutureTimeMicrosecond :: Microseconds -> IO TimeMicrosecond
getFutureTimeMicrosecond (Microseconds us) = do
    let diff = microSecondsToUnixDiffTime us
    c <- getTimeMicrosecond
    let future = c `addUnixDiffTime` diff
    return future

addMicroseconds :: TimeMicrosecond -> Microseconds -> TimeMicrosecond
addMicroseconds t (Microseconds n) = t `addUnixDiffTime` (microSecondsToUnixDiffTime n)
