{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.QLogger (
    QLogger,
    dirQLogger,
) where

import System.FilePath
import System.Log.FastLogger

import Network.QUIC.Imports
import Network.QUIC.Qlog
import Network.QUIC.Types

dirQLogger
    :: Maybe FilePath -> TimeMicrosecond -> CID -> ByteString -> IO (QLogger, IO ())
dirQLogger Nothing _ _ _ = do
    let qLog ~_ = return ()
        clean = return ()
    return (qLog, clean)
dirQLogger (Just dir) tim cid rl = do
    let file = dir </> (show cid <> ".qlog")
    (fastlogger, clean) <- newFastLogger1 $ LogFileNoRotate file 4096
    qlogger <- newQlogger tim rl cid fastlogger
    return (qlogger, clean)
