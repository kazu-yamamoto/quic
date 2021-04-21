{-# LANGUAGE DeriveDataTypeable #-}

module Network.QUIC.Connection.Timeout (
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

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
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

fire :: Connection -> Microseconds -> TimeoutCallback -> IO ()
fire conn (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr microseconds action'
  where
    action' = do
        open <- isConnOpen conn
        when open action `E.catch` ignore

cfire :: Connection -> Microseconds -> TimeoutCallback -> IO (IO ())
cfire conn (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    key <- registerTimeout timmgr microseconds action'
    let cancel = unregisterTimeout timmgr key
    return cancel
  where
    action' = do
        open <- isConnOpen conn
        when open action `E.catch` ignore

delay :: Microseconds -> IO ()
delay (Microseconds microseconds) = threadDelay microseconds
