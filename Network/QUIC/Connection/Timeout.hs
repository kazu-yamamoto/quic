module Network.QUIC.Connection.Timeout (
    timeout,
    fire,
    cfire,
    delay,
) where

import Control.Concurrent
import Control.Exception
import Data.Unique (Unique, newUnique)
import GHC.Conc.Sync
import Network.QUIC.Event

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Types

newtype Timeout = Timeout Unique deriving (Eq)

instance Show Timeout where
    show _ = "<<timeout>>"

instance Exception Timeout where
    toException = asyncExceptionToException
    fromException = asyncExceptionFromException

-- 'SomeException') within the computation will break the timeout behavior.
timeout :: Microseconds -> String -> IO a -> IO (Maybe a)
timeout (Microseconds n) label f
    | n < 0 = fmap Just f
    | n == 0 = return Nothing
    | otherwise = do
        -- In the threaded RTS, we use the Timer Manager to delay the
        -- (fairly expensive) 'forkIO' call until the timeout has expired.
        --
        -- An additional thread is required for the actual delivery of
        -- the Timeout exception because killThread (or another throwTo)
        -- is the only way to reliably interrupt a throwTo in flight.
        pid <- myThreadId
        ex <- fmap Timeout newUnique
        tm <- getSystemTimerManager
        -- 'lock' synchronizes the timeout handler and the main thread:
        --  * the main thread can disable the handler by writing to 'lock';
        --  * the handler communicates the spawned thread's id through 'lock'.
        -- These two cases are mutually exclusive.
        lock <- newEmptyMVar
        let handleTimeout = do
                v <- isEmptyMVar lock
                when v $ void $ forkIOWithUnmask $ \unmask -> unmask $ do
                    tid <- myThreadId
                    labelThread tid $ "timeout:" ++ label
                    v2 <- tryPutMVar lock =<< myThreadId
                    when v2 $ throwTo pid ex
            cleanupTimeout key = uninterruptibleMask_ $ do
                v <- tryPutMVar lock undefined
                if v
                    then unregisterTimeout tm key
                    else takeMVar lock >>= killThread
        handleJust
            (\e -> if e == ex then Just () else Nothing)
            (\_ -> return Nothing)
            ( bracket
                (registerTimeout tm n handleTimeout)
                cleanupTimeout
                (\_ -> fmap Just f)
            )

fire :: Connection -> Microseconds -> TimeoutCallback -> IO ()
fire conn (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    void $ registerTimeout timmgr microseconds action'
  where
    action' = do
        alive <- getAlive conn
        when alive action `catch` ignore

cfire :: Connection -> Microseconds -> TimeoutCallback -> IO (IO ())
cfire conn (Microseconds microseconds) action = do
    timmgr <- getSystemTimerManager
    key <- registerTimeout timmgr microseconds action'
    let cancel = unregisterTimeout timmgr key
    return cancel
  where
    action' = do
        alive <- getAlive conn
        when alive action `catch` ignore

delay :: Microseconds -> IO ()
delay (Microseconds microseconds) = threadDelay microseconds
