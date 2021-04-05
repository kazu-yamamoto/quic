{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Exception (
    handleLogT
  , handleLogR
  , handleLogE
  , handleLogRun
  ) where

import qualified Control.Exception as E
import qualified GHC.IO.Exception as E
import qualified System.IO.Error as E

import Network.QUIC.Logger
import Network.QUIC.Types

handleLogRun :: DebugLogger -> IO () -> IO ()
handleLogRun logAction action = E.handle handler action
  where
    handler :: E.SomeException -> IO ()
    handler se
      | Just E.ThreadKilled     <- E.fromException se = return ()
      | Just ConnectionIsClosed <- E.fromException se = return ()
      | Just InternalException  <- E.fromException se = return ()
      | otherwise = do
            case E.fromException se of
              Just e | E.ioeGetErrorType e == E.InvalidArgument -> return ()
              _ -> logAction $ bhow se

handleLogT :: DebugLogger -> IO () -> IO () -> IO ()
handleLogT logAction postProcess action = do
    ex <- E.try action
    case ex of
      Right () -> return ()
      Left se
        | Just E.ThreadKilled <- E.fromException se -> return ()
        | otherwise -> do
              logAction $ bhow se
              postProcess

-- Log and return a value
handleLogR :: forall a . (Builder -> IO a) -> IO a -> IO a
handleLogR logAction action = E.handle handler action
  where
    handler :: E.SomeException -> IO a
    handler se = logAction $ bhow se

-- Log and throw an exception
handleLogE :: (Builder -> IO ()) -> IO a -> IO a
handleLogE logAction action = E.handle handler action
  where
    handler :: E.SomeException -> IO a
    handler se@(E.SomeException e) = do
        logAction $ bhow se
        E.throwIO e
