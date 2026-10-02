{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Stopping a server through the handler it hands out.
--
-- The point of it is what it does not do.  A server used to be stopped by
-- closing the socket under the dispatcher waiting on it, which takes an IO
-- manager that can wake a thread out of a wait by closing its file
-- descriptor, and tells the peers of every connection nothing at all.
module ShutdownSpec where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import qualified Network.Socket as NS
import qualified System.Timeout as T
import Test.Hspec

import Network.QUIC
import qualified Network.QUIC.Client as C
import Network.QUIC.Internal
import Network.QUIC.Server

import Config

spec :: Spec
spec = describe "the shutdown handler" $ do
    it "ends a server that has no connection to end it through" $
        withServerSocket $ \sock -> do
            (sc, ready, stopVar) <- shutdownServerConfig
            withAsync (runWithSockets [sock] sc $ \_ -> return ()) $ \server -> do
                takeMVar ready
                stopNow <- takeMVar stopVar
                stopNow
                ended <- T.timeout 5000000 $ wait server
                ended `shouldBe` Just ()
            -- The socket is the caller's, and still is: stopping the server
            -- did not close it.
            NS.getSocketName sock `shouldReturn` serverSockAddr

    it "tells a connected client before it goes" $
        withServerSocket $ \sock -> do
            (sc, ready, stopVar) <- shutdownServerConfig
            let forever' = threadDelay 30000000
            -- Said from the server's side of the connection, not the
            -- client's: the server reaches its application once the
            -- handshake is behind it and the connection is one it has, and
            -- stopping before that is a race the client cannot see.
            serving <- newEmptyMVar
            withAsync (runWithSockets [sock] sc $ \_ -> putMVar serving () >> forever') $
                \server -> do
                    takeMVar ready
                    stopNow <- takeMVar stopVar
                    withAsync (C.run clientConfig (\_ -> forever')) $ \peer -> do
                        takeMVar serving
                        stopNow
                        -- The server first, so that a server that did not
                        -- stop is not reported as a client that was not
                        -- told.
                        ended <- T.timeout 5000000 $ wait server
                        ended `shouldBe` Just ()
                        told <- T.timeout 5000000 $ waitCatch peer
                        told `shouldSatisfy` wasToldTheServerIsClosing

-- | Whether the client ended because the server said so, rather than
--   because it waited out its idle timeout on a connection that had stopped
--   answering.
wasToldTheServerIsClosing :: Maybe (Either E.SomeException ()) -> Bool
wasToldTheServerIsClosing (Just (Left se)) = case E.fromException se of
    Just (ApplicationProtocolErrorIsReceived _ reason) -> reason == serverIsClosing
    _ -> False
wasToldTheServerIsClosing _ = False

-- | What a stopping server says, which is 'scCloseReason's default.
serverIsClosing :: ReasonPhrase
serverIsClosing = "server is closing"

-- A port of its own.  Two UDP sockets may hold one port between them, so a
-- port another spec has not finished with is not a bind that fails, it is a
-- test that reads someone else's datagrams.
serverPort :: NS.PortNumber
serverPort = 15004

serverSockAddr :: NS.SockAddr
serverSockAddr = NS.SockAddrInet serverPort $ NS.tupleToHostAddress (127, 0, 0, 1)

withServerSocket :: (NS.Socket -> IO a) -> IO a
withServerSocket = E.bracket (serverSocket ("127.0.0.1", serverPort)) NS.close

clientConfig :: ClientConfig
clientConfig = testClientConfig{ccPortName = show serverPort}

-- | A server that says when it is ready and hands out the action that stops
--   it.
shutdownServerConfig :: IO (ServerConfig, MVar (), MVar (IO ()))
shutdownServerConfig = do
    sc0 <- makeTestServerConfig
    ready <- newEmptyMVar
    stopVar <- newEmptyMVar
    let sc =
            sc0
                { scHooks = (scHooks sc0){onServerReady = putMVar ready ()}
                , scInstallShutdownHandler = putMVar stopVar
                }
    return (sc, ready, stopVar)
