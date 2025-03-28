module Network.QUIC.Connection.Timeout (
    timeout,
    fire,
    fire',
    cfire,
    delay,
) where

import Control.Concurrent
import qualified Control.Exception as E
import Network.QUIC.Event
import qualified System.Timeout as ST

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Types

timeout :: Microseconds -> String -> IO a -> IO (Maybe a)
timeout (Microseconds ms) _ action = ST.timeout ms action

fire :: Connection -> Microseconds -> TimeoutCallback -> IO ()
fire conn (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr microseconds action'
  where
    action' = do
        alive <- getAlive conn
        when alive action `E.catch` ignore

fire' :: Microseconds -> TimeoutCallback -> IO ()
fire' (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr microseconds action

cfire :: Connection -> Microseconds -> TimeoutCallback -> IO (IO ())
cfire conn (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    key <- registerTimeout timmgr microseconds action'
    let cancel = unregisterTimeout timmgr key
    return cancel
  where
    action' = do
        alive <- getAlive conn
        when alive action `E.catch` ignore

delay :: Microseconds -> IO ()
delay (Microseconds microseconds) = threadDelay microseconds
