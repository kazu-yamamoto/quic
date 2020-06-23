module Network.QUIC.Exception (
    handleLog
  , handleIOLog
  ) where

import qualified Control.Exception as E
import qualified GHC.IO.Exception as E
import qualified System.IO.Error as E

import Network.QUIC.Logger

handleLog :: DebugLogger -> IO () -> IO ()
handleLog logAction action =
    action `E.catch` handler (return ()) logAction

handleIOLog :: IO () -> DebugLogger -> IO () -> IO ()
handleIOLog cleanupAction logAction action =
    action `E.catch` handler cleanupAction logAction

handler :: IO () -> DebugLogger -> E.SomeException -> IO ()
handler cleanupAction logAction se
  | Just E.ThreadKilled <- E.fromException se = return ()
  | otherwise = do
        cleanupAction
        case E.fromException se of
          Just e | E.ioeGetErrorType e == E.InvalidArgument -> return ()
          _ -> logAction $ bhow se
