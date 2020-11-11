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
            let cc0 = addHook testClientConfig $ setOnPlainCreated $ rrBits InitialLevel
            runQUICClient cc0 waitEstablished `shouldThrow` check ProtocolViolation
            let cc1 = addHook testClientConfig $ setOnPlainCreated $ rrBits HandshakeLevel
            runQUICClient cc1 waitEstablished `shouldThrow` check ProtocolViolation
            let cc2 = addHook testClientConfig $ setOnPlainCreated $ rrBits RTT1Level
            runQUICClient cc2 waitEstablished `shouldThrow` check ProtocolViolation
        it "throws transport parameter error" $ do
            let cc0 = addHook testClientConfig $ setOnTransportParametersCreated dropInitialSourceConnectionId
            runQUICClient cc0 waitEstablished `shouldThrow` check TransportParameterError
            -- Stop the server
            let ccF = testClientConfig
            runQUICClient ccF $ \conn -> do
                waitEstablished conn
                putMVar var ()

addHook :: ClientConfig -> (Hooks -> Hooks) -> ClientConfig
addHook cc modify = cc'
  where
    conf = ccConfig cc
    hooks = confHooks conf
    hooks' = modify hooks
    conf' = conf { confHooks = hooks' }
    cc' = cc { ccConfig = conf' }

setOnPlainCreated :: (EncryptionLevel -> Plain -> Plain) -> Hooks -> Hooks
setOnPlainCreated f hooks = hooks { onPlainCreated = f }

rrBits :: EncryptionLevel -> EncryptionLevel -> Plain -> Plain
rrBits lvl0 lvl plain
  | lvl0 == lvl = plain { plainFlags = Flags 0x08 }
  | otherwise   = plain

setOnTransportParametersCreated :: (Parameters -> Parameters) -> Hooks -> Hooks
setOnTransportParametersCreated f hooks = hooks { onTransportParametersCreated = f }

dropInitialSourceConnectionId :: Parameters -> Parameters
dropInitialSourceConnectionId params = params { initialSourceConnectionId = Nothing }

check :: TransportError -> QUICError -> Bool
check te (TransportErrorOccurs te' _) = te == te'
check _  _                            = False
