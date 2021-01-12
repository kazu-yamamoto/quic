{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Logger (
    Builder
  , DebugLogger
  , bhow
  , stdoutLogger
  , dirDebugLogger
  ) where

import System.FilePath
import System.Log.FastLogger
import Data.ByteString.Builder (byteString, toLazyByteString)
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy.Char8 as BL

import Network.QUIC.Imports
import Network.QUIC.Types

-- | A type for debug logger.
type DebugLogger = Builder -> IO ()

bhow :: Show a => a -> Builder
bhow = byteString . C8.pack . show

stdoutLogger :: DebugLogger
stdoutLogger b = BL.putStrLn $ toLazyByteString b

dirDebugLogger :: Maybe FilePath -> CID -> IO (DebugLogger, IO ())
dirDebugLogger Nothing _ = do
    let dLog ~_ = return ()
        clean = return ()
    return (dLog, clean)
dirDebugLogger (Just dir) cid = do
    let file = dir </> (show cid <> ".txt")
    (fastlogger, clean) <- newFastLogger (LogFileNoRotate file 4096)
    let dLog msg = fastlogger (toLogStr msg <> "\n")
    return (dLog, clean)
