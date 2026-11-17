module Network.QUIC.Connection.Timeout (
    waitWithin,
    fire,
    fire',
    cfire,
    delay,
) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Control.Exception as E
import Network.QUIC.Event

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Types

-- | Waiting for an STM action, giving up after the time given.  The
--   deadline is waited for beside it rather than thrown at it.
waitWithin :: Microseconds -> STM a -> IO (Maybe a)
waitWithin us act = do
    expired <- registerDelay $ toDelay us
    atomically $ (Just <$> act) `orElse` (Nothing <$ (readTVar expired >>= check))

fire :: Connection -> Microseconds -> TimeoutCallback -> IO ()
fire conn us action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr (toDelay us) action'
  where
    action' = do
        alive <- getAlive conn
        when alive action `E.catch` ignore

fire' :: Microseconds -> TimeoutCallback -> IO ()
fire' us action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr (toDelay us) action

cfire :: Connection -> Microseconds -> TimeoutCallback -> IO (IO ())
cfire conn us action = do
    timmgr <- getSystemTimerManager
    key <- registerTimeout timmgr (toDelay us) action'
    let cancel = unregisterTimeout timmgr key
    return cancel
  where
    action' = do
        alive <- getAlive conn
        when alive action `E.catch` ignore

delay :: Microseconds -> IO ()
delay = threadDelay . toDelay
