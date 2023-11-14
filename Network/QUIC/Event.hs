{-# LANGUAGE CPP #-}

module Network.QUIC.Event (
    getSystemTimerManager,
    registerTimeout,
    unregisterTimeout,
    updateTimeout,
    TimerManager,
    TimeoutCallback,
    TimeoutKey,
) where
#if defined(mingw32_HOST_OS)
import GHC.Event.Windows

type TimerManager = Manager

getSystemTimerManager :: IO TimerManager
getSystemTimerManager = getSystemManager
#else
import GHC.Event
#endif
