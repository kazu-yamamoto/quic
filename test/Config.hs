{-# LANGUAGE OverloadedStrings #-}

module Config (
    makeTestServerConfig,
    makeTestServerConfigR,
    testClientConfig,
    testClientConfigR,
    setServerQlog,
    setClientQlog,
    withPipe,
    Scenario (..),
    newSessionManager,
) where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import Data.IORef
import qualified Data.List as L
import qualified Data.List.NonEmpty as NE
import Network.Socket
import Network.Socket.ByteString
import Network.TLS hiding (Version)

import Network.QUIC.Client
import Network.QUIC.Internal

makeTestServerConfig :: IO ServerConfig
makeTestServerConfig = do
    cred <-
        either error id
            <$> credentialLoadX509 "test/servercert.pem" "test/serverkey.pem"
    let credentials = Credentials [cred]
    return
        testServerConfig
            { scCredentials = credentials
            , scALPN = Just chooseALPN
            }

testServerConfig :: ServerConfig
testServerConfig =
    defaultServerConfig
        { -- Don't use "0.0.0.0" and "::" for Windows (UDP dispatching bug)
          scAddresses = [("127.0.0.1", 50003)]
        , scParameters =
            (scParameters defaultServerConfig)
                { maxIdleTimeout = Milliseconds 3000
                }
        }

makeTestServerConfigR :: IO ServerConfig
makeTestServerConfigR = do
    cred <-
        either error id
            <$> credentialLoadX509 "test/servercert.pem" "test/serverkey.pem"
    let credentials = Credentials [cred]
    return
        testServerConfigR
            { scCredentials = credentials
            , scALPN = Just chooseALPN
            }

testServerConfigR :: ServerConfig
testServerConfigR =
    defaultServerConfig
        { -- Don't use "0.0.0.0" and "::" for Windows (UDP dispatching bug)
          scAddresses = [("127.0.0.1", 50003)]
        , scParameters =
            (scParameters defaultServerConfig)
                { maxIdleTimeout = Milliseconds 3000
                }
        }

testClientConfig :: ClientConfig
testClientConfig =
    defaultClientConfig
        { ccServerName = "127.0.0.1"
        , ccPortName = "50003"
        , ccValidate = False
        , ccDebugLog = True
        , ccParameters =
            (ccParameters defaultClientConfig)
                { maxIdleTimeout = Milliseconds 3000
                }
        }

testClientConfigR :: ClientConfig
testClientConfigR =
    defaultClientConfig
        { ccServerName = "127.0.0.1"
        , ccPortName = "50002"
        , ccValidate = False
        , ccDebugLog = True
        , ccParameters =
            (ccParameters defaultClientConfig)
                { maxIdleTimeout = Milliseconds 3000
                }
        }

setServerQlog :: ServerConfig -> ServerConfig
setServerQlog sc = sc

setClientQlog :: ClientConfig -> ClientConfig
setClientQlog cc = cc

data Scenario
    = Randomly Int
    | DropClientPacket [Int]
    | DropServerPacket [Int]

withPipe :: Scenario -> IO () -> IO ()
withPipe scenario body = do
    addrC <- resolve "50002"
    let saC = addrAddress addrC
    addrS <- resolve "50003"
    let saS = addrAddress addrS
    irefC <- newIORef 0
    irefS <- newIORef 0
    E.bracket (openSocket addrC) close $ \sockC ->
        E.bracket (openSocket addrS) close $ \sockS -> do
            setSocketOption sockC ReuseAddr 1
            setSocketOption sockS ReuseAddr 1
            bind sockC saC
            connect sockS saS
            -- from client
            tid0 <- forkIO $ do
                (bs, saO) <- recvFrom sockC 2048
                connect sockC saO
                n0 <- atomicModifyIORef' irefC $ \x -> (x + 1, x)
                dropPacket0 <- shouldDrop scenario True n0
                unless dropPacket0 $ void $ send sockS bs
                forever $ do
                    bs1 <-
                        recv sockC 2048
                    n <- atomicModifyIORef' irefC $ \x -> (x + 1, x)
                    dropPacket <- shouldDrop scenario True n
                    unless dropPacket $ void $ send sockS bs1
            -- from server
            tid1 <- forkIO $ forever $ do
                bs <-
                    recv sockS 2048
                n <- atomicModifyIORef' irefS $ \x -> (x + 1, x)
                dropPacket <- shouldDrop scenario False n
                unless dropPacket $ void $ send sockC bs
            body
            killThread tid0
            killThread tid1
  where
    hints =
        defaultHints
            { addrSocketType = Datagram
            , addrFlags = [AI_NUMERICHOST]
            , addrFamily = AF_INET
            }
    resolve port =
        NE.head <$> getAddrInfo (Just hints) (Just "127.0.0.1") (Just port)
    shouldDrop (Randomly n) _ _ = do
        w <- getRandomOneByte
        return ((w `mod` fromIntegral n) == 0)
    shouldDrop (DropClientPacket ns) fromC pn
        | fromC = return (pn `elem` ns)
        | otherwise = return False
    shouldDrop (DropServerPacket ns) fromC pn
        | fromC = return False
        | otherwise = return (pn `elem` ns)

chooseALPN :: Version -> [ByteString] -> IO ByteString
chooseALPN _ver protos = return $ case mh3idx of
    Nothing -> case mhqidx of
        Nothing -> ""
        Just _ -> "hq"
    Just h3idx -> case mhqidx of
        Nothing -> "h3"
        Just hqidx -> if h3idx < hqidx then "h3" else "hq"
  where
    mh3idx = "h3" `L.elemIndex` protos
    mhqidx = "hq" `L.elemIndex` protos

newSessionManager :: IO SessionManager
newSessionManager = sessionManager <$> newIORef Nothing

sessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
sessionManager ref =
    noSessionManager
        { sessionEstablish = establish
        , sessionResume = resume
        , sessionResumeOnlyOnce = resume
        , sessionInvalidate = \_ -> return ()
        , sessionUseTicket = False
        }
  where
    establish sid sdata = writeIORef ref (Just (sid, sdata)) >> return Nothing
    resume sid = do
        mx <- readIORef ref
        case mx of
            Nothing -> return Nothing
            Just (s, d)
                | s == sid -> return $ Just d
                | otherwise -> return Nothing
