{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Logger (
    Builder,
    DebugLogger,
    bhow,
    dropIfUnwritable,
    stdoutLogger,
    dirDebugLogger,
) where

import qualified Control.Exception as E
import Data.ByteString.Builder (byteString, toLazyByteString)
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy.Char8 as BL
import System.FilePath
import System.Log.FastLogger

import Network.QUIC.Imports
import Network.QUIC.Types

-- | A type for debug logger.
type DebugLogger = Builder -> IO ()

bhow :: Show a => a -> Builder
bhow = byteString . C8.pack . show

-- | Running a write that describes a connection, dropping the message if
--   it cannot be written.  Shared with the qlog writer, which is called
--   from the same threads and must be no more able to end them.
--
-- A debug logger must not be able to end the connection it is describing.
-- It is called from the protocol threads, six of which run under nested
-- 'concurrently_' and take the rest down with them, so an exception from
-- the write ends the connection over a line of debug output.  A daemon has
-- no stdout to write to -- it is closed, or a pipe whose reader has gone --
-- and that is what mighty was doing with a debug directory set:
--
--   debug: handshaker: \<stdout\>: hPutBuf: invalid argument (Bad file descriptor)
--   debug: handshaker: \<stdout\>: hPutBuf: resource vanished (Broken pipe)
--
-- The peer saw a handshake that never finished, or, once a connection
-- ending of something in here said so, an INTERNAL_ERROR.  It came and went
-- because a stdout that is not a terminal is block-buffered: most writes
-- only fill the buffer and it is the flush that fails.
--
-- Only 'E.IOException' is dropped.  An asynchronous exception is not one,
-- so cancelling a thread that is logging still cancels it.
dropIfUnwritable :: IO () -> IO ()
dropIfUnwritable action = action `E.catch` \(_ :: E.IOException) -> return ()

stdoutLogger :: DebugLogger
stdoutLogger b = dropIfUnwritable $ BL.putStrLn $ toLazyByteString b

dirDebugLogger :: Maybe FilePath -> CID -> IO (DebugLogger, IO ())
dirDebugLogger Nothing _ = do
    let dLog ~_ = return ()
        clean = return ()
    return (dLog, clean)
dirDebugLogger (Just dir) cid = do
    let file = dir </> (show cid <> ".txt")
    (fastlogger, clean) <- newFastLogger1 (LogFileNoRotate file 4096)
    let dLog msg = do
            dropIfUnwritable $ fastlogger (toLogStr msg <> "\n")
            stdoutLogger msg
    return (dLog, clean)
