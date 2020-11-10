{-# LANGUAGE OverloadedStrings #-}

module ErrorSpec where

import Control.Concurrent
import Data.ByteString ()
import Test.Hspec

import Network.QUIC
import Network.QUIC.Internal

import Config

spec :: Spec
spec = do
    sc <- runIO $ makeTestServerConfig
    var <- runIO newEmptyMVar
    -- To kill this server, one connection must be established
    _ <- runIO $ forkIO $ runQUICServer sc $ \conn -> do
        waitEstablished conn
        _ <- takeMVar var
        stopQUICServer conn
    describe "error handling" $ do
        it "through protocol violation" $ do
            let cc0 = testClientConfig
                cc = cc0 { ccConfig = (ccConfig cc0) { confHooks = defaultHooks { onPlainCreated = rrBits }}}
            runQUICClient cc waitEstablished `shouldThrow` check ProtocolViolation
            -- Stop the server
            let cc' = testClientConfig
            runQUICClient cc' $ \conn -> do
                waitEstablished conn
                putMVar var ()

rrBits :: Plain -> Plain
rrBits plain = plain { plainFlags = Flags 0x08 }

check :: TransportError -> QUICError -> Bool
check te (TransportErrorOccurs te' _) = te == te'
check _  _                            = False
