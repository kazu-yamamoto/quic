{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE InterruptibleFFI #-}

module Network.QUIC.Client.WatchDog (
    watchDog,
    watchDogWith,
    watchSocket,
) where

import Control.Concurrent
import qualified Control.Exception as E
import Foreign.C.Types

import Network.QUIC.Imports

-- | Running the action on every change of the network the OS reports,
--   until the OS cannot report them.
watchDog :: IO () -> IO ()
watchDog = watchDogWith c_open_socket c_watch_socket c_close_socket

-- | 'watchDog' with the socket calls given.  The watch returns 0 for an
--   event, -1 to be tried again and anything else to give up.  A socket
--   that could not be opened is never watched: a watch on it fails at
--   once, and trying it again spun.
watchDogWith
    :: IO CInt -> (CInt -> IO CInt) -> (CInt -> IO CInt) -> IO () -> IO ()
watchDogWith open watch clse action = E.bracket open release $ \s ->
    when (s >= 0) $ loop s
  where
    release s = when (s >= 0) $ void $ clse s
    loop s = do
        ret <- watch s
        case ret of
            0 -> do
                action
                -- prevent calling "migrate" frequently
                threadDelay 100000
                loop s
            -1 -> loop s
            _ -> return ()

-- | One watch on the socket, as 'watchDog' does.
watchSocket :: CInt -> IO CInt
watchSocket = c_watch_socket

foreign import ccall unsafe "open_socket"
    c_open_socket :: IO CInt

foreign import ccall interruptible "watch_socket"
    c_watch_socket :: CInt -> IO CInt

foreign import ccall unsafe "close_socket"
    c_close_socket :: CInt -> IO CInt
