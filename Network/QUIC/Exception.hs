module Network.QUIC.Exception (
    handlerIO
  , handler
  , E.handle
  , E.catch
  ) where

import qualified Control.Exception as E
import qualified GHC.IO.Exception as E
import qualified System.IO.Error as E

import Network.QUIC.Connection
import Network.QUIC.Types

handlerIO :: Connection -> E.SomeException -> IO ()
handlerIO conn se
  | Just E.ThreadKilled <- E.fromException se = return ()
  | otherwise = do
        putInput conn $ InpError ConnectionIsClosed
        case E.fromException se of
          Just e | E.ioeGetErrorType e == E.InvalidArgument -> return ()
          _ -> print se

handler :: E.SomeException -> IO ()
handler se
  | Just E.ThreadKilled <- E.fromException se = return ()
  | otherwise = case E.fromException se of
          Just e | E.ioeGetErrorType e == E.InvalidArgument -> return ()
          _ -> print se
