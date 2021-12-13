{-# LANGUAGE CPP #-}
module Network.QUIC.Event(getSystemTimerManager, registerTimeout, unregisterTimeout, updateTimeout, TimerManager, TimeoutCallback, TimeoutKey) where
#ifndef mingw32_HOST_OS
-- Re-export GHC.Event
import GHC.Event
#else
import Control.Concurrent
import System.Timeout
-- In case of Windows
-- We don't really need a timer manager type
data TimerManager = TimerConstructor

type TimeoutCallback = IO ()

data TimeOutMsg = Stop | Update Int

data TimeoutKey = TimeKeyConstructor ThreadId (MVar TimeOutMsg)

getSystemTimerManager :: IO TimerManager
getSystemTimerManager = pure TimerConstructor

registerTimeout :: TimerManager -> Int -> TimeoutCallback -> IO TimeoutKey
registerTimeout _ n callback = do
    mvar <- newEmptyMVar :: IO (MVar TimeOutMsg)
    TimeKeyConstructor <$> forkIO (
        let action time = do
                msg <- timeout time (takeMVar mvar)
                case msg of
                    Nothing -> callback
                    Just ms ->
                        case ms of
                            Stop -> pure ()
                            Update n2 -> action n2
        in action n) <*> pure mvar

unregisterTimeout :: TimerManager -> TimeoutKey -> IO ()
unregisterTimeout _ (TimeKeyConstructor _ messages) = tryPutMVar messages Stop >> return ()

updateTimeout :: TimerManager -> TimeoutKey -> Int -> IO ()
updateTimeout _ (TimeKeyConstructor _ messages) n = tryPutMVar messages (Update n) >> return ()
#endif
