{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Exception (
    handleLog
  , handleLogR
  , handleLogE
  ) where

import qualified Control.Exception as E
import qualified GHC.IO.Exception as E
import qualified System.IO.Error as E

import Network.QUIC.Logger

handleLog :: DebugLogger -> IO () -> IO ()
handleLog logAction action = E.handle handler action
  where
    handler :: E.SomeException -> IO ()
    handler se
      | Just E.ThreadKilled <- E.fromException se = return ()
      | otherwise = do
            case E.fromException se of
              Just e | E.ioeGetErrorType e == E.InvalidArgument -> return ()
              _ -> logAction $ bhow se

handleLogR :: forall a . (Builder -> IO a) -> IO a -> IO a
handleLogR logAction action = E.handle handler action
  where
    handler :: E.SomeException -> IO a
    handler se = logAction $ bhow se

handleLogE :: (Builder -> IO ()) -> IO a -> IO a
handleLogE logAction action = E.handle handler action
  where
    handler :: E.SomeException -> IO a
    handler se@(E.SomeException e) = do
        logAction $ bhow se
        E.throwIO e
