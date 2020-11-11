{-# LANGUAGE OverloadedStrings #-}

module ErrorSpec where

import Control.Concurrent
import Data.ByteString ()
import System.Timeout
import Test.Hspec
import Network.QUIC
import Network.QUIC.Internal

import Config

{-
import System.Environment
import qualified Test.Hspec.Core.Runner as H

main :: IO ()
main = do
    [host,port] <- getArgs
    let cc = defaultClientConfig {
            ccServerName = host
          , ccPortName   = port
          }
    withArgs [] (H.runSpec (spec' cc) H.defaultConfig) >>= H.evaluateSummary
-}

setup :: IO (IO ())
setup = do
    sc <- makeTestServerConfig
    var <- newEmptyMVar
    -- To kill this server, one connection must be established
    _ <- forkIO $ runQUICServer sc $ \conn -> do
        waitEstablished conn
        _ <- takeMVar var
        stopQUICServer conn
    threadDelay 50000 -- give time to the server to get ready
    return $ putMVar var ()

teardown :: IO () -> IO ()
teardown action = do
    -- Stop the server
    let ccF = testClientConfig
    runQUICClient ccF $ \conn -> do
        waitEstablished conn
        action

spec :: Spec
spec = beforeAll setup $ afterAll teardown $ spec' testClientConfig

runC :: ClientConfig -> (Connection -> IO a) -> IO (Maybe a)
runC cc body = timeout 500000 $ runQUICClient cc body

spec' :: ClientConfig -> SpecWith a
spec' cc = do
    describe "A QUIC server" $ do
        it "throws protocol violation if reserved bits are non-zero" $ \_ -> do
            let cc0 = addHook cc $ setOnPlainCreated $ rrBits InitialLevel
            runC cc0 waitEstablished `shouldThrow` check ProtocolViolation
            let cc1 = addHook cc $ setOnPlainCreated $ rrBits HandshakeLevel
            runC cc1 waitEstablished `shouldThrow` check ProtocolViolation
            let cc2 = addHook cc $ setOnPlainCreated $ rrBits RTT1Level
            runC cc2 waitEstablished `shouldThrow` check ProtocolViolation
        it "throws transport parameter error if initial source connection is missing" $ \_ -> do
            let cc0 = addHook cc $ setOnTransportParametersCreated dropInitialSourceConnectionId
            runC cc0 waitEstablished `shouldThrow` check TransportParameterError

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
