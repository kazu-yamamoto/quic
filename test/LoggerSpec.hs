{-# LANGUAGE OverloadedStrings #-}

module LoggerSpec where

import qualified Control.Exception as E
import Control.Monad (when)
import Data.IORef
import GHC.IO.Handle (hDuplicate, hDuplicateTo)
import System.Directory
import System.FilePath
import System.IO
import System.Log.FastLogger (FastLogger)
import Test.Hspec

import Network.QUIC.Internal

spec :: Spec
spec = do
    -- A debug logger is called from the protocol threads, six of which run
    -- under nested concurrently_ and take the rest down with them, so a
    -- write that throws ends the connection it was describing.  A daemon
    -- has no stdout to write to: mighty's connections were ending on
    --
    --   debug: handshaker: <stdout>: hPutBuf: invalid argument
    --                                (Bad file descriptor)
    --
    -- and the peer saw a handshake that never finished.
    describe "stdoutLogger" $
        it "drops a message stdout cannot take" $
            withUnwritableStdout (stdoutLogger "a line no one can receive")
                `shouldReturn` ()

    describe "dirDebugLogger" $
        -- The file is what the caller asked for, and it is still written
        -- when stdout is gone.
        it "writes the file when stdout cannot be written" $
            withDebugDir $ \dir -> do
                (dLog, clean) <- dirDebugLogger (Just dir) cid
                withUnwritableStdout $ dLog "a line the file can take"
                clean
                readFile (dir </> show cid <> ".txt")
                    `shouldReturn` "a line the file can take\n"
    -- The qlog writer is called from the sender, the receiver and the
    -- closer, the same protocol threads as the debug logger, so it must be
    -- no more able to end them.  A qlog directory is asked for by name, as
    -- a debug directory is, and the disk it is on can fill.
    describe "newQlogger" $ do
        it "does not throw when the header cannot be written" $ do
            tim <- getTimeMicrosecond
            _ <- newQlogger tim "server" cid full
            return ()

        it "drops a message that cannot be written" $ do
            tim <- getTimeMicrosecond
            qlogger <- newQlogger tim "server" cid full
            qlogger (QDebug "a line the disk has no room for" tim)
                `shouldReturn` ()

        -- Only an IOException is dropped.  Nothing else is, and an
        -- asynchronous exception is not one, so cancelling a thread that is
        -- writing a qlog still cancels it.
        it "lets anything that is not an IOException through" $ do
            tim <- getTimeMicrosecond
            -- The header is the first write, and it has to get through for
            -- there to be a logger to try.
            afterTheHeader <- brokenAfter 1
            qlogger <- newQlogger tim "server" cid afterTheHeader
            qlogger (QDebug "not the disk's fault" tim)
                `shouldThrow` errorCall "boom"
  where
    full :: FastLogger
    full _ = E.throwIO $ userError "no space left on device"
    brokenAfter :: Int -> IO FastLogger
    brokenAfter k = do
        ref <- newIORef (0 :: Int)
        return $ \_ -> do
            n <- atomicModifyIORef' ref $ \x -> (x + 1, x)
            when (n >= k) $ E.throwIO $ E.ErrorCall "boom"
    cid = makeCID "\x01\x02\x03\x04\x05\x06\x07\x08"

-- | Running an action with a stdout every write throws on, and putting the
--   real one back afterwards.  stdout is redirected rather than closed:
--   hspec reports through it, and a handle that is only redirected can be
--   restored from the duplicate however the action ends.
withUnwritableStdout :: IO a -> IO a
withUnwritableStdout action = do
    saved <- hDuplicate stdout
    let redirected = withFile "/dev/null" ReadMode $ \h -> do
            hDuplicateTo h stdout
            action `E.finally` hDuplicateTo saved stdout
    redirected `E.finally` hClose saved

withDebugDir :: (FilePath -> IO a) -> IO a
withDebugDir = E.bracket newDir removePathForcibly
  where
    newDir = do
        tmp <- getTemporaryDirectory
        let dir = tmp </> "quic-logger-spec"
        removePathForcibly dir
        createDirectory dir
        return dir
