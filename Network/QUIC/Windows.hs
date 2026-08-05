{-# LANGUAGE CPP #-}

module Network.QUIC.Windows (
    windowsThreadBlockHack,
) where

#if defined(mingw32_HOST_OS)
import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad

windowsThreadBlockHack :: IO a -> IO a
windowsThreadBlockHack act = do
    var <- newEmptyMVar :: IO (MVar (Either E.SomeException a))
    void . forkIO $ E.try act >>= putMVar var
    res <- takeMVar var
    case res of
        Left e -> print e >> E.throwIO e
        Right r -> return r
#else
windowsThreadBlockHack :: IO a -> IO a
windowsThreadBlockHack = id
#endif
