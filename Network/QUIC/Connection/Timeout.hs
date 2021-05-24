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
import qualified Control.Exception as OldE
import qualified Control.Monad.IO.Unlift as E
import Data.Typeable
import GHC.Event
import System.IO.Unsafe (unsafePerformIO)

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Types

data TimeoutException = TimeoutException deriving (Show, Typeable)

instance OldE.Exception TimeoutException

globalTimeoutQ :: TQueue (IO ())
globalTimeoutQ = unsafePerformIO newTQueueIO
{-# NOINLINE globalTimeoutQ #-}

timeouter :: IO ()
timeouter = forever $ join $ atomically (readTQueue globalTimeoutQ)

timeout :: Microseconds -> IO a -> IO (Maybe a)
timeout ms action = E.withRunInIO $ \run -> timeout' ms $ run action

timeout' :: Microseconds -> IO a -> IO (Maybe a)
timeout' (Microseconds microseconds) action = do
    tid <- myThreadId
    timmgr <- getSystemTimerManager
    let killMe = OldE.throwTo tid TimeoutException
        onTimeout = atomically $ writeTQueue globalTimeoutQ killMe
        setup = registerTimeout timmgr microseconds onTimeout
        cleanup key = unregisterTimeout timmgr key
    OldE.handle (\TimeoutException -> return Nothing) $
        OldE.bracket setup cleanup $ \_ -> Just <$> action

fire :: Connection -> Microseconds -> TimeoutCallback -> IO ()
fire conn (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr microseconds action'
  where
    action' = do
        alive <- getAlive conn
        when alive action `OldE.catch` ignore

cfire :: Connection -> Microseconds -> TimeoutCallback -> IO (IO ())
cfire conn (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    key <- registerTimeout timmgr microseconds action'
    let cancel = unregisterTimeout timmgr key
    return cancel
  where
    action' = do
        alive <- getAlive conn
        when alive action `OldE.catch` ignore

delay :: Microseconds -> IO ()
delay (Microseconds microseconds) = threadDelay microseconds
