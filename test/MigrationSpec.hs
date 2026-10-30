module MigrationSpec where

import Control.Concurrent
import Control.Concurrent.Async (mapConcurrently)
import Control.Concurrent.STM
import Control.Monad (void)
import Network.Socket (connect, getSocketName)
import Test.Hspec

import Network.QUIC.Internal

import Config
import PacketSpec (makeConnections)

spec :: Spec
spec = do
    serverConf <- runIO makeTestServerConfig
    -- The dispatcher calls this for every packet that arrives from an
    -- address the connection has not seen, before anything has
    -- authenticated the packet, and 'findPathInfo' knows the address in use
    -- and the one before it and nothing else.  A peer that moves its port
    -- -- which asks no spoofing of it -- is therefore unknown on every
    -- packet it sends.  One of those packets is a migration; the rest are
    -- nothing.  See #167.
    describe "claimMigration" $ do
        it "gives the migration to one caller and refuses the rest" $ do
            (_, serverConn) <- makeConnections serverConf Version1
            rs <- mapConcurrently (const $ claimMigration serverConn) [1 .. 200 :: Int]
            length (filter id rs) `shouldBe` 1
        it "refuses while the validation it started is unfinished" $ do
            (_, serverConn) <- makeConnections serverConf Version1
            claimMigration serverConn `shouldReturn` True
            claimMigration serverConn `shouldReturn` False

    -- 'rebind' swaps a new socket in and has to end the reader of the old
    -- one.  It used to do that by closing the old socket under it, which
    -- works only because the event manager tells a blocked thread that the
    -- descriptor closed; the reader is told now.  Retiring the wrong one of
    -- the two leaves a connection whose socket nobody reads, and both
    -- readers are alive either way, so this watches which variable is set.
    -- See #173.
    describe "rebind" $ do
        it "retires the reader of the socket it replaced, not the new one" $ do
            (clientConn, _) <- makeConnections serverConf Version1
            oldSock <- getSocket clientConn
            oldRetired <- getSocketRetire clientConn
            rebind clientConn
            newSock <- getSocket clientConn
            newRetired <- getSocketRetire clientConn
            readTVarIO oldRetired `shouldReturn` True
            readTVarIO newRetired `shouldReturn` False
            (newSock == oldSock) `shouldBe` False
            -- The reader 'rebind' forked is on the new socket; let it go.
            atomically $ writeTVar newRetired True

        it "leaves its socket for the sender when rebind has swapped it out" $ do
            (clientConn, _) <- makeConnections serverConf Version1
            sock <- getSocket clientConn
            peersa <- peerSockAddr <$> getPathInfo clientConn
            connect sock peersa
            retired <- getSocketRetire clientConn
            done <- newEmptyMVar
            void $ forkIO $ readerClient retired sock clientConn >> putMVar done ()
            threadDelay 100000
            -- What 'rebind' does: swap first, retire second.
            newSock <- natRebinding peersa
            newRetired <- newTVarIO False
            _ <- swapSocket clientConn newSock newRetired
            atomically $ writeTVar retired True
            returned <- timeout (Microseconds 2000000) "retired reader" $ takeMVar done
            returned `shouldBe` Just ()
            -- Left, not closed: the sender could still be inside a send on
            -- it, and it is the sender which closes it.
            void $ getSocketName sock
            closeRetiredSockets clientConn
            getSocketName sock `shouldThrow` anyException
            atomically $ writeTVar newRetired True

        it "leaves its socket even when it is killed rather than told" $ do
            (clientConn, _) <- makeConnections serverConf Version1
            sock <- getSocket clientConn
            peersa <- peerSockAddr <$> getPathInfo clientConn
            connect sock peersa
            retired <- getSocketRetire clientConn
            tid <- forkIO $ readerClient retired sock clientConn
            threadDelay 100000
            newSock <- natRebinding peersa
            newRetired <- newTVarIO False
            _ <- swapSocket clientConn newSock newRetired
            -- As 'killReaders' does: thrown at, not told.
            killThread tid
            threadDelay 100000
            closeRetiredSockets clientConn
            getSocketName sock `shouldThrow` anyException
            atomically $ writeTVar newRetired True

        it "leaves its socket for the sender when the connection goes idle" $ do
            (clientConn, _) <- makeConnections serverConf Version1
            sock <- getSocket clientConn
            peersa <- peerSockAddr <$> getPathInfo clientConn
            connect sock peersa
            setMinIdleTimeout clientConn $ Microseconds 100000
            retired <- getSocketRetire clientConn
            done <- newEmptyMVar
            void $ forkIO $ readerClient retired sock clientConn >> putMVar done ()
            returned <- timeout (Microseconds 2000000) "idle reader" $ takeMVar done
            returned `shouldBe` Just ()
            void $ getSocketName sock
            closeRetiredSockets clientConn
            getSocketName sock `shouldThrow` anyException

        it "closes a socket it was left even if nothing drains it" $ do
            (clientConn, _) <- makeConnections serverConf Version1
            peersa <- peerSockAddr <$> getPathInfo clientConn
            sock <- natRebinding peersa
            -- getSocketName says nothing of an unbound socket on Windows.
            connect sock peersa
            retireSocket clientConn sock
            void $ getSocketName sock
            -- No sender to drain it, so the teardown is what closes it.
            freeResources clientConn
            getSocketName sock `shouldThrow` anyException

        it "lets a retired reader return, leaving its socket open" $ do
            (clientConn, _) <- makeConnections serverConf Version1
            sock <- getSocket clientConn
            -- The reader waits for the socket to be bound, and on Windows
            -- getSocketName says so only once it is.  A client binds it by
            -- sending; nothing is sent here, so connect does it instead.
            peersa <- peerSockAddr <$> getPathInfo clientConn
            connect sock peersa
            retired <- getSocketRetire clientConn
            done <- newEmptyMVar
            void $ forkIO $ readerClient retired sock clientConn >> putMVar done ()
            threadDelay 100000
            atomically $ writeTVar retired True
            returned <- timeout (Microseconds 2000000) "retired reader" $ takeMVar done
            returned `shouldBe` Just ()
            -- The socket belongs to whoever retired the reader: it is still
            -- open for them to close, which getSocketName would not be on a
            -- closed one.
            void $ getSocketName sock
