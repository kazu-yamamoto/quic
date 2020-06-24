{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Logger (
    Builder
  , DebugLogger
  , QLogger
  , QManager
  , bhow
  , stdoutLogger
  , dirDebugLogger
  , dirQLogger
  ) where

import System.FilePath
import System.Log.FastLogger
import Data.ByteString.Builder (Builder, byteString, toLazyByteString)
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy.Char8 as BL

import Network.QUIC.Qlog
import Network.QUIC.Types

type DebugLogger = Builder -> IO ()
type QLogger     = QlogMsg -> IO ()
type QManager    = IO ()

bhow :: Show a => a -> Builder
bhow = byteString . C8.pack . show

stdoutLogger :: DebugLogger
stdoutLogger b = BL.putStrLn $ toLazyByteString b

dirDebugLogger :: Maybe FilePath -> CID -> IO (DebugLogger, IO ())
dirDebugLogger Nothing _ = do
    let dLog _  = return ()
        clean = return ()
    return (dLog, clean)
dirDebugLogger (Just dir) cid = do
    let file = dir </> (show cid <> ".txt")
    (fastlogger, clean) <- newFastLogger (LogFileNoRotate file 4096)
    let dLog msg = fastlogger (toLogStr msg)
    return (dLog, clean)

dirQLogger :: Maybe FilePath -> CID -> IO (QLogger, IO (), IO ())
dirQLogger Nothing _ = do
    let qLog _  = return ()
        clean = return ()
        qmgr = return ()
    return (qLog, clean, qmgr)
dirQLogger (Just dir) cid = do
    let file = dir </> (show cid <> ".qlog")
    (fastlogger, clean) <- newFastLogger $ LogFileNoRotate file 4096
    qq <- newQlogQ
    let qLog msg = writeQlogQ qq msg
        qmgr = newQlogger qq "client" (fromCID cid) fastlogger
    return (qLog, clean, qmgr)
