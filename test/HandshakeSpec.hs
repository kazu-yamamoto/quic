module HandshakeSpec where

import Control.Concurrent.Async
import Control.Monad
import Network.TLS
import Test.Hspec

import Network.QUIC
import Network.QUIC.Connection

spec :: Spec
spec = do
    describe "handshake" $ do
        it "can handshake in the normal case" $ do
            let cc = defaultClientConfig
                sc = defaultServerConfig
            testHandshake cc sc
        it "can handshake in the case of TLS hello retry" $ do
            let cc = defaultClientConfig
                sc = defaultServerConfig {
                       scConfig = defaultConfig {
                                    confGroups = [P256]
                                  }
                     }
            testHandshake cc sc
        it "can handshake in the case of QUIC retry" $ do
            let cc = defaultClientConfig
                sc = defaultServerConfig {
                       scRequireRetry = True
                     }
            testHandshake cc sc

testHandshake :: ClientConfig -> ServerConfig -> IO ()
testHandshake cc sc = void $ concurrently client server
  where
    sc' = sc {
            scKey  = "test/serverkey.pem"
          , scCert = "test/servercert.pem"
          }
    client = withQUICClient cc $ \qc -> do
        conn <- connect qc
        isConnectionOpen conn `shouldReturn` True
        close conn
    server = withQUICServer sc' $ \qs -> do
        conn <- accept qs
        isConnectionOpen conn `shouldReturn` True
        close conn
