module Network.QUIC.Time (
    getTimeSecond
  , getTimeMillisecond
  , getElapsedTimeSecond
  , getElapsedTimeMillisecond
  , getPastTimeMillisecond
  , TimeSecond
  , TimeMillisecond
  , fromTimeSecond
  , toTimeSecond
  , Seconds(..)
  , Milliseconds(..)
  ) where

import qualified Data.Hourglass as H
import Data.Int (Int64)
import Data.Word (Word64)
import System.Hourglass

----------------------------------------------------------------

type TimeSecond = H.Elapsed
type TimeMillisecond = H.ElapsedP

fromTimeSecond :: TimeSecond -> Word64
fromTimeSecond (H.Elapsed (H.Seconds t)) = fromIntegral t

toTimeSecond :: Word64 -> TimeSecond
toTimeSecond = H.Elapsed . H.Seconds . fromIntegral

----------------------------------------------------------------

getTimeSecond :: IO TimeSecond
getTimeSecond = timeCurrent

getTimeMillisecond :: IO TimeMillisecond
getTimeMillisecond = timeCurrentP

----------------------------------------------------------------

newtype Seconds = Seconds Int64 deriving (Eq, Ord, Show)
newtype Milliseconds = Milliseconds Int64 deriving (Eq, Ord, Show)

----------------------------------------------------------------

getElapsedTimeSecond :: TimeSecond -> IO Seconds
getElapsedTimeSecond base = do
    H.Seconds s <- (base `H.timeDiff`) <$> getTimeSecond
    return $ Seconds s

getElapsedTimeMillisecond :: TimeMillisecond -> IO Milliseconds
getElapsedTimeMillisecond base = Milliseconds . relativeTime base <$> timeCurrentP

relativeTime :: TimeMillisecond -> TimeMillisecond -> Int64
relativeTime t1 t2 = fromIntegral (s * 1000 + (n `div` 1000000))
  where
   (H.Seconds s, H.NanoSeconds n) = t2 `H.timeDiffP` t1

----------------------------------------------------------------

getPastTimeMillisecond :: Milliseconds -> IO TimeMillisecond
getPastTimeMillisecond milli = (`timeDel` milli) <$> getTimeMillisecond

timeDel :: TimeMillisecond -> Milliseconds -> TimeMillisecond
timeDel (H.ElapsedP sec nano) milli
  | nano' >= sec1 = H.ElapsedP sec (nano' - sec1)
  | otherwise     = H.ElapsedP (sec - 1) nano'
  where
    milliToNano (Milliseconds n) = H.NanoSeconds (n * 1000000)
    sec1 = 1000000000
    nano' = nano + sec1 - milliToNano milli
