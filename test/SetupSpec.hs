{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | What a connection or a server setup leaves behind when it fails.
--
-- 'createServerConnection' and 'run's own @setup@ are the acquire of their
-- bracket, so the release does not run when they throw and whatever they
-- have taken is freed by nobody.
--
-- Only the first has a test here.  What @setup@ leaks is a bound UDP socket,
-- and whether a port is still taken is not a portable question: on Linux two
-- UDP sockets with SO_REUSEADDR may hold the same address and port at once,
-- so the bind that is supposed to fail succeeds and the bind that is
-- supposed to succeed says nothing about the leak.  A first attempt at it
-- hung every CI job on the former.
module SetupSpec where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import System.Directory (createDirectory, listDirectory)
import System.FilePath
import System.IO
import Test.Hspec

import Network.QUIC
import qualified Network.QUIC.Client as C
import Network.QUIC.Internal
import Network.QUIC.Server

import Config

spec :: Spec
spec = do
    -- The qlog is opened before the debug log, and a debug log that cannot
    -- be opened is a real failure: a directory that is not there, or the
    -- "openFile: resource busy" of a client and a server in one process
    -- pointed at one directory.
    describe "a server connection setup that fails" $
        it "does not leave the qlog it had already opened open" $
            withTempDir "quic-setup-spec" $ \dir -> do
                let qdir = dir </> "qlog"
                createDirectory qdir
                sc0 <- makeTestServerConfig
                -- Waiting for the port to be bound.  Without this the
                -- client can start first, hear nothing, and give up on its
                -- idle timeout having never made the server open a qlog at
                -- all: the directory is then empty and the test fails
                -- saying so rather than saying anything about handles.  One
                -- run in five on a busy machine.
                ready <- newEmptyMVar
                let sc =
                        sc0
                            { scQLog = Just qdir
                            , scDebugLog = Just (dir </> "not-a-directory")
                            , scHooks = (scHooks sc0){onServerReady = putMVar ready ()}
                            }
                    cc =
                        testClientConfig
                            { ccParameters =
                                (ccParameters testClientConfig)
                                    { maxIdleTimeout = Milliseconds 1000
                                    }
                            }
                withAsync (run sc $ \_ -> return ()) $ \_ -> do
                    takeMVar ready
                    C.run cc (\_ -> return ())
                        `shouldThrow` (\(_ :: QUICException) -> True)
                -- If the handle is still open, GHC's own lock on the file
                -- says so.
                files <- listDirectory qdir
                files `shouldNotSatisfy` null
                mapM_ (waitUnlocked . (qdir </>)) files

-- | Waiting for a file to come unlocked, which is to say for the handle on
--   it to be closed.
--
-- The server forks a connection for each Initial it cannot place, and a
-- client that hears nothing retransmits, so when the client gives up there
-- may be an attempt still on its way out holding the file.  Taking that for
-- a leak would be a test that fails when the machine is busy; a leaked
-- handle, on the other hand, is held for the life of the process, so
-- waiting tells the two apart.
waitUnlocked :: FilePath -> IO ()
waitUnlocked file = go (100 :: Int)
  where
    open = withFile file WriteMode $ \_ -> return ()
    go 0 = open -- out of patience: let the lock speak for itself
    go n = do
        r <- E.try open
        case r of
            Right () -> return ()
            Left (_ :: E.IOException) -> threadDelay 20000 >> go (n - 1)
