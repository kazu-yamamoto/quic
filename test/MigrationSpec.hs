{-# LANGUAGE OverloadedStrings #-}

module MigrationSpec where

import Control.Concurrent (newEmptyMVar, putMVar, takeMVar, threadDelay)
import Control.Concurrent.Async (mapConcurrently, withAsync)
import qualified Data.ByteString as BS
import Test.Hspec

import Network.QUIC
import qualified Network.QUIC.Client as C
import Network.QUIC.Internal
import Network.QUIC.Server

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

    -- 'rebind' swaps the socket, leaves the old reader taking what still
    -- arrives on the old path, and then retires it.  The connection has to
    -- go on working across that: see #173.
    describe "NAT rebinding" $ do
        sc0 <- runIO makeTestServerConfig
        ready <- runIO newEmptyMVar
        let sc = sc0{scHooks = (scHooks sc0){onServerReady = putMVar ready ()}}
        it "keeps the connection once the old socket is retired" $ do
            let payload = BS.replicate 1000 0
                -- Read everything, then answer: the answer comes back on
                -- the socket the client swapped in, so a client reader
                -- retired with the wrong socket loses it.
                server conn = do
                    strm <- acceptStream conn
                    n <- BS.length . BS.concat <$> readAll strm id
                    sendStream strm $ BS.replicate n 1
                    shutdownStream strm
                readAll strm front = do
                    bs <- recvStream strm 2048
                    if BS.null bs
                        then return (front [])
                        else readAll strm (front . (bs :))
            withAsync (run sc server) $ \_ -> do
                takeMVar ready
                C.run testClientConfig $ \conn -> do
                    strm <- stream conn
                    sendStream strm payload
                    controlConnection conn NATRebinding `shouldReturn` True
                    -- Past the five milliseconds after which the old
                    -- socket is closed and its reader retired.
                    threadDelay 200000
                    sendStream strm payload
                    shutdownStream strm
                    echo <- BS.concat <$> readAll strm id
                    BS.length echo `shouldBe` (2 * BS.length payload)
