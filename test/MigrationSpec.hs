{-# LANGUAGE OverloadedStrings #-}

module MigrationSpec where

import Control.Concurrent
import Control.Concurrent.Async (concurrently, mapConcurrently, wait, withAsync)
import Control.Concurrent.STM
import Control.Monad (forM, forM_, void)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as Short
import Network.Control (txfLimit)
import Network.Socket (connect, getSocketName, withFdSocket)
import qualified System.Timeout as T
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
    -- RFC 9000 Sec 8.2.1: a challenge lost was not sent again, so one
    -- loss failed the validation.  It is sent again, each time with a new
    -- payload, and a late answer to an earlier one still counts.
    describe "validatePath" $
        it "sends the challenge again with a new payload until answered" $ do
            (_, serverConn) <- makeConnections serverConf Version1
            pathInfo <- getPathInfo serverConn >>= newPathInfo . peerSockAddr
            withAsync (validatePath serverConn pathInfo Nothing) $ \validation -> do
                let challenge = do
                        out <- T.timeout 3000000 $ atomically $ takeOutputSTM serverConn
                        case out of
                            Just (OutPathProbe _ _ [PathChallenge pdat]) -> return pdat
                            _ -> fail "no challenge"
                p1 <- challenge
                p2 <- challenge
                p2 `shouldNotBe` p1
                checkResponse serverConn p1
                wait validation `shouldReturn` True

    -- RFC 9000 Sec 9.5: a client that changed its CID to move gets a new
    -- CID of its own on the new path, while the old path keeps the old
    -- one; the old one was given up at once, and the old path's challenge
    -- went out with the new.
    -- #223: a NEW_CONNECTION_ID retiring every CID it does not bring
    -- left none to use, and the connection ended with INTERNAL_ERROR.
    describe "addPeerCIDAndRetire" $ do
        let cid :: Int -> CID
            cid i = toCID $ BS.replicate 8 $ fromIntegral i
            srt i = StatelessResetToken $ Short.toShort $ BS.replicate 16 $ fromIntegral i
            info i = newCIDInfo i (cid i) (srt i)
        it "moves to the new CID when all the others are retired" $ do
            (_, serverConn) <- makeConnections serverConf Version1
            addPeerCIDAndRetire serverConn (info 1) 1 `shouldReturn` Just [0]
            getPeerCID serverConn `shouldReturn` cid 1
        it "lets a CID exceed the limit when the excess is retired" $ do
            (_, serverConn) <- makeConnections serverConf Version1
            let lim = activeConnectionIdLimit $ getMyParameters serverConn
            forM_ [1 .. lim - 1] $ \i ->
                addPeerCIDAndRetire serverConn (info i) 0 `shouldReturn` Just []
            addPeerCIDAndRetire serverConn (info lim) 0 `shouldReturn` Nothing
            addPeerCIDAndRetire serverConn (info lim) lim
                `shouldReturn` Just [0 .. lim - 1]
            getPeerCID serverConn `shouldReturn` cid lim

    describe "validateMigration" $ do
        let next conn = do
                out <- T.timeout 4000000 $ atomically $ takeOutputSTM conn
                maybe (fail "no output") return out
            setup = do
                (_, serverConn) <- makeConnections serverConf Version1
                old <- getPeerCID serverConn
                let new = toCID "\1\2\3\4\5\6\7\8"
                    srt = StatelessResetToken $ Short.toShort $ BS.replicate 16 1
                _ <- addPeerCID serverConn $ newCIDInfo 1 new srt
                pathInfo <- getPathInfo serverConn >>= newPathInfo . peerSockAddr
                return (serverConn, old, new, pathInfo)
            challenges conn = do
                o1 <- next conn
                o2 <- next conn
                case (o1, o2) of
                    ( OutPathProbe _ mcid [PathChallenge _]
                        , OutPathProbe _ Nothing [PathChallenge pdat]
                        ) -> return (mcid, pdat)
                    _ -> fail "not two challenges"
        it "keeps the old CID for the old path and retires it once moved" $ do
            (conn, old, new, pathInfo) <- setup
            withAsync (validateMigration conn pathInfo True) $ \v -> do
                (mcid, pdat) <- challenges conn
                mcid `shouldBe` Just old
                getPeerCID conn `shouldReturn` new
                checkResponse conn pdat
                wait v `shouldReturn` True
                o <- next conn
                case o of
                    OutControl RTT1Level [RetireConnectionID 0] -> return ()
                    _ -> fail "old CID not retired"
        it "goes back to the old CID and retires the new one if not moved" $ do
            (conn, old, _, pathInfo) <- setup
            withAsync (validateMigration conn pathInfo True) $ \v -> do
                (mcid, _) <- challenges conn
                mcid `shouldBe` Just old
                wait v `shouldReturn` False
                getPeerCID conn `shouldReturn` old
                -- After the challenges sent again.
                let retired = do
                        o <- next conn
                        case o of
                            OutControl RTT1Level [RetireConnectionID n] -> return n
                            _ -> retired
                retired `shouldReturn` 1

    -- The PTO probe is for the path in use.  A PATH_CHALLENGE for another
    -- path took it, and the probe went to that path instead.
    describe "a path probe" $
        it "leaves a pending PTO probe for the path in use" $ do
            (_, serverConn) <- makeConnections serverConf Version1
            let ldcc = connLDCC serverConn
            -- What 'run' sets up, so that the window is open.
            setInitialCongestionWindow ldcc 1200
            pathInfo <- getPathInfo serverConn >>= newPathInfo . peerSockAddr
            atomically $ writeTVar (addressValidated pathInfo) True
            sendPing ldcc RTT1Level
            pdat <- newPathData
            sendOutput serverConn $ OutPathProbe pathInfo Nothing [PathChallenge pdat]
            atomically (isEmptyPingSTM ldcc) `shouldReturn` False

    -- RFC 9001 Sec 4.6.2: a stream opened as 0-RTT is found rejected is
    -- held to the server's new limit too.  It read the old parameters,
    -- missed the reset that ran before it was in the table, and kept them.
    describe "resetTxStreamLimits" $
        it "reaches a stream opened while it runs" $ do
            (clientConn, _) <- makeConnections serverConf Version1
            base <- getPeerParameters clientConn
            let params n = base{initialMaxStreamDataBidiRemote = n}
            limits <- forM [0, 4 .. 4 * 1999] $ \sid -> do
                setPeerParameters clientConn $ params 100
                (strm, _) <-
                    concurrently
                        (addStream clientConn sid)
                        ( do
                            setPeerParameters clientConn $ params 10
                            resetTxStreamLimits clientConn $ params 10
                        )
                txfLimit <$> atomically (readStreamFlowTx strm)
            filter (/= 10) limits `shouldBe` []

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

        it "closes the socket it replaced even if the connection ends first" $ do
            (clientConn, _) <- makeConnections serverConf Version1
            oldSock <- getSocket clientConn
            -- A reader on the socket, as 'runClient' has.
            peersa <- peerSockAddr <$> getPathInfo clientConn
            connect oldSock peersa
            retired <- getSocketRetire clientConn
            forkManaged clientConn "QUIC reader" $ readerClient retired oldSock clientConn
            threadDelay 100000
            rebind clientConn
            -- Over at once, torn down as 'runClient' does.
            setDead clientConn
            killReaders clientConn
            freeResources clientConn
            -- A closed socket has its descriptor taken away.
            withFdSocket oldSock return `shouldReturn` (-1)

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
            newSock <- natRebinding False peersa
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
            newSock <- natRebinding False peersa
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
            sock <- natRebinding False peersa
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
