{-# LANGUAGE CPP #-}

-- | Making a blocking socket call interruptible on Windows.
module Network.QUIC.Windows (
    windowsThreadBlockHack,
) where

#if defined(mingw32_HOST_OS)
import Control.Concurrent
import qualified Control.Exception as E
import GHC.Conc.Sync (labelThread)

-- | Running a blocking call on a thread of its own, and waiting for it
--   here.
--
-- A thread blocked in a socket call on Windows cannot be reached by an
-- asynchronous exception: neither 'killThread' nor the timeouts quic builds
-- on the event manager get at it, and the readiness this package used to
-- wait for instead -- 'threadWaitReadSTM' and so the socket's STM wrappers
-- -- is not available under the native I/O manager at all, because
-- completion ports have nothing to say about a socket being readable.
--
-- So the call goes to a thread of its own and this one waits on an MVar,
-- which is interruptible.  It is the classic answer; warp has used it since
-- 3.2.17.
--
-- The call is abandoned rather than cancelled.  When this thread is
-- interrupted the forked one stays in the call until the socket is closed,
-- so this belongs only where the socket is closed soon after -- and where
-- another reader starting on the same socket in the meantime would do no
-- harm, since the two would then race for the next datagram.
--
-- On every other platform the thread can be reached and this is 'id'.
windowsThreadBlockHack :: IO a -> IO a
windowsThreadBlockHack act = do
    var <- newEmptyMVar :: IO (MVar (Either E.SomeException a))
    tid <- forkIO $ E.try act >>= putMVar var
    labelThread tid "QUIC blocking call"
    res <- takeMVar var
    case res of
        Left e -> E.throwIO e
        Right r -> return r
#else
windowsThreadBlockHack :: IO a -> IO a
windowsThreadBlockHack = id
#endif
