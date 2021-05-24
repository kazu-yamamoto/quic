{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Exception (
    handleLogT
  , handleLogUnit
  ) where

import qualified Control.Exception as OldE
import qualified GHC.IO.Exception as E
import qualified System.IO.Error as E
import qualified UnliftIO.Exception as E

import Network.QUIC.Logger

-- Catch all exceptions including asynchronous ones.
handleLogUnit :: DebugLogger -> IO () -> IO ()
handleLogUnit logAction action = action `OldE.catch` handler
  where
    handler :: OldE.SomeException -> IO ()
    handler se = case E.fromException se of
      -- threadWait: invalid argument (Bad file descriptor)
      Just e | E.ioeGetErrorType e == E.InvalidArgument -> return ()
      -- recvBuf: does not exist (Connection refused)
      Just e | E.ioeGetErrorType e == E.NoSuchThing     -> return ()
      _                                                 -> logAction $ bhow se

-- Log and throw an exception
handleLogT :: DebugLogger -> IO a -> IO a
handleLogT logAction action = action `E.catchAny` handler
  where
    handler (E.SomeException e) = do
        logAction $ bhow e
        E.throwIO e
