{-# LANGUAGE DeriveDataTypeable #-}

module Network.QUIC.Connection.Timeout (
    timeout
  , fire
  , cfire
  , delay
  ) where

import Data.Typeable
import Network.QUIC.Event
import UnliftIO.Concurrent
import qualified UnliftIO.Exception as E

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Types

data TimeoutException = TimeoutException String deriving (Show, Typeable)

instance E.Exception TimeoutException where
  fromException = E.asyncExceptionFromException
  toException = E.asyncExceptionToException

timeout :: Microseconds -> String -> IO a -> IO (Maybe a)
timeout (Microseconds ms) dmsg action = do
    tid <- myThreadId
    timmgr <- getSystemTimerManager
    let killMe = E.throwTo tid $ TimeoutException dmsg
        setup = registerTimeout timmgr ms killMe
        cleanup key = unregisterTimeout timmgr key
    E.handleSyncOrAsync (\(TimeoutException _) -> return Nothing) $
        E.bracket setup cleanup $ \_ -> Just <$> action

fire :: Connection -> Microseconds -> TimeoutCallback -> IO ()
fire conn (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr microseconds action'
  where
    action' = do
        alive <- getAlive conn
        when alive action `E.catchSyncOrAsync` ignore

cfire :: Connection -> Microseconds -> TimeoutCallback -> IO (IO ())
cfire conn (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    key <- registerTimeout timmgr microseconds action'
    let cancel = unregisterTimeout timmgr key
    return cancel
  where
    action' = do
        alive <- getAlive conn
        when alive action `E.catchSyncOrAsync` ignore

delay :: Microseconds -> IO ()
delay (Microseconds microseconds) = threadDelay microseconds
