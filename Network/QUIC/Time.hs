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
  , MilliSeconds(..)
  ) where

import Data.Hourglass
import Data.Int (Int64)
import Data.Word (Word64)
import System.Hourglass

----------------------------------------------------------------

type TimeSecond = Elapsed
type TimeMillisecond = ElapsedP

fromTimeSecond :: TimeSecond -> Word64
fromTimeSecond (Elapsed (Seconds t)) = fromIntegral t

toTimeSecond :: Word64 -> TimeSecond
toTimeSecond = Elapsed . Seconds . fromIntegral

----------------------------------------------------------------

getTimeSecond :: IO TimeSecond
getTimeSecond = timeCurrent

getTimeMillisecond :: IO TimeMillisecond
getTimeMillisecond = timeCurrentP

----------------------------------------------------------------

getElapsedTimeSecond :: TimeSecond -> IO Int
getElapsedTimeSecond base = do
    Seconds s <- (base `timeDiff`) <$> getTimeSecond
    return $ fromIntegral s

getElapsedTimeMillisecond :: TimeMillisecond -> IO Int
getElapsedTimeMillisecond base = relativeTime base <$> timeCurrentP

relativeTime :: ElapsedP -> ElapsedP -> Int
relativeTime t1 t2 = fromIntegral (s * 1000 + (n `div` 1000000))
  where
   (Seconds s, NanoSeconds n) = t2 `timeDiffP` t1

----------------------------------------------------------------

newtype MilliSeconds = MilliSeconds Int64 deriving (Eq, Show)

getPastTimeMillisecond :: MilliSeconds -> IO ElapsedP
getPastTimeMillisecond milli = (`timeDel` milli) <$> getTimeMillisecond

timeDel :: ElapsedP -> MilliSeconds -> ElapsedP
timeDel (ElapsedP sec nano) milli
  | nano' >= sec1 = ElapsedP sec (nano' - sec1)
  | otherwise     = ElapsedP (sec - 1) nano'
  where
    milliToNano (MilliSeconds n) = NanoSeconds (n * 1000000)
    sec1 = 1000000000
    nano' = nano + sec1 - milliToNano milli
