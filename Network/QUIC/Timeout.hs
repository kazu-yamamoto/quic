{-# LANGUAGE DeriveDataTypeable #-}

module Network.QUIC.Timeout (
    timeouter
  , timeout
  , fire
  , cfire
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

globalTimeoutQ :: TQueue (IO ())
globalTimeoutQ = unsafePerformIO newTQueueIO
{-# NOINLINE globalTimeoutQ #-}

timeouter :: IO ()
timeouter = forever $ join $ atomically (readTQueue globalTimeoutQ)

timeout :: Microseconds -> IO a -> IO (Maybe a)
timeout (Microseconds microseconds) action = do
    tid <- myThreadId
    timmgr <- getSystemTimerManager
    let killMe = E.throwTo tid TimeoutException
        onTimeout = atomically $ writeTQueue globalTimeoutQ killMe
        setup = registerTimeout timmgr microseconds onTimeout
        cleanup key = unregisterTimeout timmgr key
    E.handle (\TimeoutException -> return Nothing) $
        E.bracket setup cleanup $ \_ -> Just <$> action

fire :: Microseconds -> TimeoutCallback -> IO ()
fire (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr microseconds (action `E.catch` ignore)


cfire :: Microseconds -> TimeoutCallback -> IO (IO ())
cfire (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    key <- registerTimeout timmgr microseconds (action `E.catch` ignore)
    let cancel = unregisterTimeout timmgr key
    return cancel

delay :: Microseconds -> IO ()
delay (Microseconds microseconds) = threadDelay microseconds
