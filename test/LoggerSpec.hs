{-# LANGUAGE OverloadedStrings #-}

module LoggerSpec where

import qualified Control.Exception as E
import GHC.IO.Handle (hDuplicate, hDuplicateTo)
import System.Directory
import System.FilePath
import System.IO
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
  where
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
