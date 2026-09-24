{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.QLogger (
    QLogger,
    dirQLogger,
) where

import qualified Data.ByteString.Char8 as C8
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
-- The role belongs in the name, not only in the vantage_point inside.  A
-- client names its file after the peer CID and a server after the original
-- destination CID, which for one connection are the same value -- so a client
-- and a server in one process, pointed at one directory, ask for the same
-- file.  LogFileNoRotate takes the file exclusively, and the second one to
-- ask does not get a degraded log, it gets "openFile: resource busy" thrown
-- through its connection setup.  For the server that is the connection, gone
-- before it began.
dirQLogger (Just dir) tim cid rl = do
    let file = dir </> (show cid <> "-" <> C8.unpack rl <> ".qlog")
    (fastlogger, clean) <- newFastLogger1 $ LogFileNoRotate file 4096
    qlogger <- newQlogger tim rl cid fastlogger
    return (qlogger, clean)
