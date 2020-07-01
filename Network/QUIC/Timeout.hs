{-# LANGUAGE DeriveDataTypeable #-}

module Network.QUIC.Timeout (
    timeouter
  , timeout
  , fire
  , delay
  ) where

import Control.Concurrent
import Control.Concurrent.STM
import Control.Exception as E
import Data.Typeable
import GHC.Event
import System.IO.Unsafe (unsafePerformIO)

import Network.QUIC.Imports
import Network.QUIC.Types

data TimeoutException = TimeoutException deriving (Show, Typeable)

instance Exception TimeoutException

globalTimeoutQ :: TQueue ThreadId
globalTimeoutQ = unsafePerformIO newTQueueIO
{-# NOINLINE globalTimeoutQ #-}

timeouter :: IO ()
timeouter = forever $ do
    tid <- atomically (readTQueue globalTimeoutQ)
    E.throwTo tid TimeoutException

timeout :: Microseconds -> IO a -> IO (Maybe a)
timeout (Microseconds microseconds) action = do
    pid <- myThreadId
    tm <- getSystemTimerManager
    let setup = registerTimeout tm microseconds $
            atomically $ writeTQueue globalTimeoutQ pid
        cleanup key = unregisterTimeout tm key
    E.handle (\TimeoutException -> return Nothing) $
        E.bracket setup cleanup $ \_ -> Just <$> action

fire :: Microseconds -> TimeoutCallback -> IO ()
fire (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr microseconds action

delay :: Microseconds -> IO ()
delay (Microseconds microseconds) = threadDelay microseconds
