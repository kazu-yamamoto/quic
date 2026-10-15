module MigrationSpec where

import Control.Concurrent.Async (mapConcurrently)
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
