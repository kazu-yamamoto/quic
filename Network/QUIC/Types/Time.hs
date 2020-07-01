module Network.QUIC.Types.Time (
    Seconds(..)
  , Milliseconds(..)
  , milliToMicro
  , fromTimeSecond
  , toTimeSecond
  , TimeSecond
  , TimeMillisecond
  , getTimeSecond
  , getTimeMillisecond
  , getElapsedTimeSecond
  , getElapsedTimeMillisecond
  , getPastTimeMillisecond
  ) where

import Data.Int (Int64)
import Data.UnixTime
import Foreign.C.Types (CTime(..))

----------------------------------------------------------------

newtype Seconds = Seconds Int64 deriving (Eq, Ord, Show)
newtype Milliseconds = Milliseconds Int64 deriving (Eq, Ord, Show)

{-# INLINE milliToMicro #-}
milliToMicro :: Milliseconds -> Int
milliToMicro (Milliseconds n) = fromIntegral n * 1000

----------------------------------------------------------------

newtype TimeSecond = TimeSecond Seconds deriving (Eq, Ord, Show)
type TimeMillisecond = UnixTime

fromTimeSecond :: TimeSecond -> Int64
fromTimeSecond (TimeSecond (Seconds t)) = t

toTimeSecond :: Int64 -> TimeSecond
toTimeSecond = TimeSecond . Seconds

----------------------------------------------------------------

getTimeSecond :: IO TimeSecond
getTimeSecond = do
    CTime s <- utSeconds <$> getUnixTime
    return $ toTimeSecond s

getTimeMillisecond :: IO TimeMillisecond
getTimeMillisecond = getUnixTime

----------------------------------------------------------------

getElapsedTimeSecond :: TimeSecond -> IO Seconds
getElapsedTimeSecond base = do
    c<- getTimeSecond
    let elapsed = fromTimeSecond c - fromTimeSecond base
    return $ Seconds elapsed

getElapsedTimeMillisecond :: TimeMillisecond -> IO Milliseconds
getElapsedTimeMillisecond base = do
    c <- getTimeMillisecond
    let UnixDiffTime (CTime s) u = c `diffUnixTime` base
        elapsed = fromIntegral (s * 1000 + (fromIntegral u `div` 1000))
    return $ Milliseconds elapsed

----------------------------------------------------------------

getPastTimeMillisecond :: Milliseconds -> IO TimeMillisecond
getPastTimeMillisecond (Milliseconds m) = do
    let diff = microSecondsToUnixDiffTime $ negate (m * 1000)
    c <- getTimeMillisecond
    let past = c `addUnixDiffTime` diff
    return past
