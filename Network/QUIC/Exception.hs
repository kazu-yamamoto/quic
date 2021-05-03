{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Exception (
    handleLogT
  , handleLogE
  , handleLogUnit
  ) where

import qualified Control.Exception as E
import qualified GHC.IO.Exception as E
import qualified System.IO.Error as E

import Network.QUIC.Logger
import Network.QUIC.Types

handleLogUnit :: DebugLogger -> IO () -> IO ()
handleLogUnit logAction action = E.handle handler action
  where
    handler :: E.SomeException -> IO ()
    handler se
      | Just E.ThreadKilled     <- E.fromException se     = return ()
      | otherwise = case E.fromException se of
          -- threadWait: invalid argument (Bad file descriptor)
          Just e | E.ioeGetErrorType e == E.InvalidArgument -> return ()
          -- recvBuf: does not exist (Connection refused)
          Just e | E.ioeGetErrorType e == E.NoSuchThing     -> return ()
          _                                                 -> logAction $ bhow se

handleLogT :: DebugLogger -> IO () -> IO ()
handleLogT logAction action = E.handle handler action
  where
    handler se@(E.SomeException e)
      | Just E.ThreadKilled        <- E.fromException se = return ()
      | Just BreakForever          <- E.fromException se = return ()
      | otherwise                                        = do
            logAction $ bhow se
            E.throwIO e

-- Log and throw an exception
handleLogE :: DebugLogger -> IO a -> IO a
handleLogE logAction action = E.handle handler action
  where
    handler :: E.SomeException -> IO a
    handler se@(E.SomeException e) = do
        logAction $ bhow se
        E.throwIO e
