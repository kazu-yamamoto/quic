module Network.QUIC.Time (
    getElapsedTime
  , timeCurrent
  , timeCurrentP
  , timeDiff
  , timeDel
  , Elapsed(..)
  , ElapsedP(..)
  , Seconds(..)
  , MilliSeconds(..)
  ) where

import Data.Hourglass
import Data.Int (Int64)
import System.Hourglass

----------------------------------------------------------------

getElapsedTime :: ElapsedP -> IO Int
getElapsedTime base = relativeTime base <$> timeCurrentP

relativeTime :: ElapsedP -> ElapsedP -> Int
relativeTime t1 t2 = fromIntegral (s * 1000 + (n `div` 1000000))
  where
   (Seconds s, NanoSeconds n) = t2 `timeDiffP` t1

newtype MilliSeconds = MilliSeconds Int64 deriving (Eq, Show)

timeDel :: ElapsedP -> MilliSeconds -> ElapsedP
timeDel (ElapsedP sec nano) milli
  | nano' >= sec1 = ElapsedP sec (nano' - sec1)
  | otherwise     = ElapsedP (sec - 1) nano'
  where
    milliToNano (MilliSeconds n) = NanoSeconds (n * 1000000)
    sec1 = 1000000000
    nano' = nano + sec1 - milliToNano milli

