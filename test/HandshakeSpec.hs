module HandshakeSpec where


import Control.Concurrent.Async
import qualified Control.Exception as E
import Control.Monad
import Data.IORef
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
            testHandshake cc sc FullHandshake
        it "can handshake in the case of TLS hello retry" $ do
            let cc = defaultClientConfig
                sc = defaultServerConfig {
                       scConfig = defaultConfig {
                                    confGroups = [P256]
                                  }
                     }
            testHandshake cc sc HelloRetryRequest
        it "can handshake in the case of QUIC retry" $ do
            let cc = defaultClientConfig
                sc = defaultServerConfig {
                       scRequireRetry = True
                     }
            testHandshake cc sc FullHandshake
        it "can handshake in the case of resumption" $ do
            ref <- newIORef Nothing
            smgr <- newSessionManager
            let cc = defaultClientConfig {
                       ccConfig = defaultConfig {
                                    confSessionManager = sessionManager ref
                                  }
                     }
                sc = defaultServerConfig {
                       scConfig = defaultConfig {
                                    confSessionManager = smgr
                                  }
                     }
                makeCc = do
                    msession <- readIORef ref
                    return $ cc { ccResume = msession }
            testHandshake2 makeCc sc (FullHandshake, PreSharedKey)

testHandshake :: ClientConfig -> ServerConfig -> HandshakeMode13 -> IO ()
testHandshake cc sc mode = void $ concurrently client server
  where
    sc' = sc {
            scKey  = "test/serverkey.pem"
          , scCert = "test/servercert.pem"
          }
    client = withQUICClient cc $ \qc -> do
        conn <- connect qc
        isConnectionOpen conn `shouldReturn` True
        getTLSMode conn `shouldReturn` mode
        close conn
    server = withQUICServer sc' $ \qs -> do
        conn <- accept qs
        isConnectionOpen conn `shouldReturn` True
        getTLSMode conn `shouldReturn` mode
        close conn

testHandshake2 :: IO ClientConfig -> ServerConfig -> (HandshakeMode13, HandshakeMode13) -> IO ()
testHandshake2 makeCc sc (mode1, mode2) = void $ concurrently client server
  where
    sc' = sc {
            scKey  = "test/serverkey.pem"
          , scCert = "test/servercert.pem"
          }
    handler (E.SomeException e) = print e
    runClient cc mode = E.handle handler $ withQUICClient cc $ \qc -> do
        conn <- connect qc
        isConnectionOpen conn `shouldReturn` True
        getTLSMode conn `shouldReturn` mode
        close conn
    client = do
        cc1 <- makeCc
        runClient cc1 mode1
        cc2 <- makeCc
        runClient cc2 mode2
    runServer qs = do
        conn <- accept qs
        isConnectionOpen conn `shouldReturn` True
        close conn
    server = E.handle handler $ withQUICServer sc' $ \qs -> do
        runServer qs
        runServer qs

newSessionManager :: IO SessionManager
newSessionManager = sessionManager <$> newIORef Nothing

sessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
sessionManager ref = SessionManager {
    sessionEstablish      = establish
  , sessionResume         = resume
  , sessionResumeOnlyOnce = resume
  , sessionInvalidate     = \_ -> return ()
  }
  where
    establish sid sdata = writeIORef ref $ Just (sid,sdata)
    resume sid = do
        mx <- readIORef ref
        case mx of
          Nothing -> return Nothing
          Just (s,d)
            | s == sid  -> return $ Just d
            | otherwise -> return Nothing
