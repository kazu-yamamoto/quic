{-# LANGUAGE CPP #-}

module Network.QUIC.Windows (
    windowsThreadBlockHack,
) where

#if defined(mingw32_HOST_OS)
import Control.Concurrent
import qualified Control.Exception as CE
import Control.Monad

windowsThreadBlockHack :: IO a -> IO a
windowsThreadBlockHack act = do
    var <- newEmptyMVar :: IO (MVar (Either CE.SomeException a))
    -- Catch and rethrow even async exceptions, so don't bother with UnliftIO
    void . forkIO $ CE.try act >>= putMVar var
    res <- takeMVar var
    case res of
        Left e -> print e >> CE.throwIO e
        Right r -> return r
#else
windowsThreadBlockHack :: IO a -> IO a
windowsThreadBlockHack = id
#endif
