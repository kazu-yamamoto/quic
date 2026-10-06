{-# LANGUAGE OverloadedStrings #-}

module LoggerSpec where

import qualified Control.Exception as E
import Control.Monad (when)
import qualified Data.ByteString.Char8 as BS
import Data.IORef
import qualified GHC.IO.Exception as E
import GHC.IO.Handle (hDuplicate, hDuplicateTo)
import System.Directory
import System.FilePath
import System.IO
import qualified System.IO.Error as E
import System.Log.FastLogger (FastLogger)
import Test.Hspec

import Network.QUIC.Internal

import Config

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
            onUnwritableStdout
                (stdoutLogger "a line no one can receive")
                (`shouldBe` ())

    -- What the two above rest on, where a stdout that throws is not to be
    -- had.
    describe "dropIfUnwritable" $ do
        it "drops an IOException" $
            dropIfUnwritable (E.throwIO $ userError "no space left on device")
                `shouldReturn` ()
        it "lets anything else through" $
            dropIfUnwritable (E.throwIO $ E.ErrorCall "boom")
                `shouldThrow` errorCall "boom"

    describe "dirDebugLogger" $
        -- The file is what the caller asked for, and it is still written
        -- when stdout is gone.
        it "writes the file when stdout cannot be written" $
            withTempDir "quic-logger-spec" $ \dir -> do
                (dLog, clean) <- dirDebugLogger (Just dir) cid
                onUnwritableStdout (dLog "a line the file can take") $ \() -> do
                    clean
                    -- Strictly: a lazy read leaves the handle open until the
                    -- content is demanded, and Windows will not delete a
                    -- file that is open.
                    BS.readFile (dir </> show cid <> ".txt")
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
--   real one back afterwards.  'Nothing' where stdout cannot be redirected
--   at all.
--
-- stdout is redirected rather than closed: hspec reports through it, and a
-- handle that is only redirected can be restored from the duplicate however
-- the action ends.  Any handle open for reading does for the stand-in, since
-- what makes the write throw is the mode GHC holds the handle in and not
-- anything the system does -- a file of our own rather than the null device,
-- which is \"\/dev\/null\" on one platform and \"NUL\" on another.
--
-- 'hDuplicateTo' is @dup2@ on the device underneath, and the native handle
-- the Windows I\/O manager gives a standard stream does not implement it:
-- @dup2@ is left at its default, which throws.  Asking the handle rather
-- than asking which operating system this is, because the handle is what the
-- test needs something of.
withUnwritableStdout :: IO a -> IO (Maybe a)
withUnwritableStdout action = do
    tmp <- getTemporaryDirectory
    let file = tmp </> "quic-logger-spec-readable"
    writeFile file ""
    saved <- hDuplicate stdout
    let redirected = withFile file ReadMode $ \h -> do
            swapped <- E.try $ hDuplicateTo h stdout
            case swapped of
                Left e
                    | E.ioeGetErrorType e == E.UnsupportedOperation ->
                        return Nothing
                    | otherwise -> E.throwIO e
                Right () ->
                    Just <$> action `E.finally` hDuplicateTo saved stdout
    redirected `E.finally` hClose saved

-- | Running what needs a stdout that throws, or saying why it was not run.
onUnwritableStdout :: IO a -> (a -> Expectation) -> Expectation
onUnwritableStdout action check = do
    r <- withUnwritableStdout action
    case r of
        Nothing -> pendingWith "stdout cannot be redirected on this handle"
        Just x -> check x
