{-# LANGUAGE DeriveDataTypeable #-}

module Network.QUIC.Timeout (
    timeouter
  , timeout
  , fire
  ) where

import Control.Concurrent
import Control.Concurrent.STM
import Control.Exception as E
import Data.Typeable
import GHC.Event
import System.IO.Unsafe (unsafePerformIO)

import Network.QUIC.Imports

data TimeoutException = TimeoutException deriving (Show, Typeable)

instance Exception TimeoutException

globalTimeoutQ :: TQueue ThreadId
globalTimeoutQ = unsafePerformIO newTQueueIO
{-# NOINLINE globalTimeoutQ #-}

timeouter :: IO ()
timeouter = forever $ do
    tid <- atomically (readTQueue globalTimeoutQ)
    E.throwTo tid TimeoutException

timeout :: Int -> IO a -> IO (Maybe a)
timeout microseconds action = do
    pid <- myThreadId
    tm <- getSystemTimerManager
    let setup = registerTimeout tm microseconds $
            atomically $ writeTQueue globalTimeoutQ pid
        cleanup key = unregisterTimeout tm key
    E.handle (\TimeoutException -> return Nothing) $
        E.bracket setup cleanup $ \_ -> Just <$> action

fire :: Int -> TimeoutCallback -> IO ()
fire microseconds action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr microseconds action
