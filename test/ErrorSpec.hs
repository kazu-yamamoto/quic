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
        it "throws protocol violation" $ do
            let cc0 = addHook testClientConfig $ rrBits InitialLevel
            runQUICClient cc0 waitEstablished `shouldThrow` check ProtocolViolation
            let cc1 = addHook testClientConfig $ rrBits HandshakeLevel
            runQUICClient cc1 waitEstablished `shouldThrow` check ProtocolViolation
            let cc2 = addHook testClientConfig $ rrBits RTT1Level
            runQUICClient cc2 waitEstablished `shouldThrow` check ProtocolViolation
            -- Stop the server
            let ccF = testClientConfig
            runQUICClient ccF $ \conn -> do
                waitEstablished conn
                putMVar var ()

addHook :: ClientConfig -> (EncryptionLevel -> Plain -> Plain) -> ClientConfig
addHook cc modify = cc'
  where
    conf = ccConfig cc
    hooks = confHooks conf
    hooks' = hooks { onPlainCreated = modify }
    conf' = conf { confHooks = hooks' }
    cc' = cc { ccConfig = conf' }

rrBits :: EncryptionLevel -> EncryptionLevel -> Plain -> Plain
rrBits lvl0 lvl plain
  | lvl0 == lvl = plain { plainFlags = Flags 0x08 }
  | otherwise   = plain

check :: TransportError -> QUICError -> Bool
check te (TransportErrorOccurs te' _) = te == te'
check _  _                            = False
