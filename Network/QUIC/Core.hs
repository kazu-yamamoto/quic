{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Core where

import Control.Concurrent
import qualified Control.Exception as E
import Data.IORef
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB
import qualified Network.TLS as TLS
import Network.TLS.QUIC
import System.Timeout

import Network.QUIC.Client
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Handshake
import Network.QUIC.Imports
import Network.QUIC.Receiver
import Network.QUIC.Sender
import Network.QUIC.Server
import Network.QUIC.Socket
import Network.QUIC.Types

----------------------------------------------------------------

-- | Running a QUIC client.
runQUICClient :: ClientConfig -> (Connection -> IO a) -> IO a
runQUICClient conf client = do
    when (null $ confVersions $ ccConfig conf) $ E.throwIO NoVersionIsSpecified
    E.bracket (connect conf) close client

-- | Connecting the server specified in 'ClientConfig' and returning a 'Connection'.
connect :: ClientConfig -> IO Connection
connect conf = do
    let firstVersion = head $ confVersions $ ccConfig conf
    ex0 <- E.try $ connect' firstVersion
    case ex0 of
      Right conn0 -> return conn0
      Left se0 -> case check se0 of
        Left  se0' -> E.throwIO se0'
        Right ver -> do
            ex1 <- E.try $ connect' ver
            case ex1 of
              Right conn1 -> return conn1
              Left se1 -> case check se1 of
                Left  se1' -> E.throwIO se1'
                Right _    -> E.throwIO VersionNegotiationFailed
  where
    connect' ver = do
        (conn,cls) <- createClientConnection conf ver
        handshakeClientConnection conf conn `E.onException` cls
        return conn
    check se
      | Just e@(TLS.Error_Protocol _) <- E.fromException se =
                Left $ HandshakeFailed $ show $ errorToAlertDescription e
      | Just (NextVersion ver) <- E.fromException se = Right ver
      | Just (e :: QUICError)  <- E.fromException se = Left e
      | otherwise = Left $ BadThingHappen se

createClientConnection :: ClientConfig -> Version -> IO (Connection, IO ())
createClientConnection conf@ClientConfig{..} ver = do
    s0 <- udpClientConnectedSocket ccServerName ccPortName
    sref <- newIORef s0
    q <- newClientRecvQ
    let cls = do
            s <- readIORef sref
            NS.close s
        send bss = do
            s <- readIORef sref
            void $ NSB.sendMany s bss
        recv = recvClient q
    myCID   <- newCID
    peerCID <- newCID
    let logAction = confLog ccConfig peerCID
    conn <- clientConnection conf ver myCID peerCID logAction send recv cls
    -- killed by "close s0"
    void $ forkIO $ readerClient conf s0 q conn
    return (conn,cls)

handshakeClientConnection :: ClientConfig -> Connection -> IO ()
handshakeClientConnection conf@ClientConfig{..} conn = do
    setToken conn $ resumptionToken ccResumption
    tid0 <- forkIO $ sender   conn
    tid1 <- forkIO $ receiver conn
    tid2 <- forkIO $ resender conn
    setThreadIds conn [tid0,tid1,tid2]
    handshakeClient conf conn `E.onException` clearThreads conn
    setConnectionOpen conn

----------------------------------------------------------------

-- | Running a QUIC server.
--   The action is executed with a new connection
--   in a new lightweight thread.
runQUICServer :: ServerConfig -> (Connection -> IO ()) -> IO ()
runQUICServer conf server = handleLog logAction $ do
    mainThreadId <- myThreadId
    E.bracket setup teardown $ \(route,_) -> forever $ do
        acc <- readAcceptQ $ acceptQueue route
        let create = createServerConnection conf route acc mainThreadId
        void $ forkIO $ E.bracket create close server
  where
    logAction msg = putStrLn ("runQUICServer: " ++ msg)
    setup = do
        route <- newServerRoute
        -- fixme: the case where sockets cannot be created.
        ssas <- mapM  udpServerListenSocket $ scAddresses conf
        tids <- mapM (runRouter route) ssas
        return (route, tids)
    teardown (route, tids) = do
        killTokenManager $ tokenMgr route
        mapM_ killThread tids
    runRouter route ssa@(s,_) = forkFinally (router conf route ssa) (\_ -> NS.close s)

createServerConnection :: ServerConfig -> ServerRoute -> Accept -> ThreadId -> IO Connection
createServerConnection conf route acc mainThreadId = E.handle tlserr $ do
    let Accept ver myCID peerCID oCID mysa peersa0 q register unregister retried = acc
    s0 <- udpServerConnectedSocket mysa peersa0
    sref <- newIORef (s0,peersa0)
    void $ forkIO $ readerServer s0 q -- killed by "close s0"
    let logAction = confLog (scConfig conf) $ originalCID oCID
    logAction $ "My CID: " ++ show myCID ++ "\n"
    logAction $ "Peer CID: " ++ show peerCID ++ "\n"
    logAction $ "Original CID: " ++ show oCID ++ "\n"
    logAction $ "My socket address: " ++ show mysa ++ "\n"
    logAction $ "Peer socket address: " ++ show peersa0 ++ "\n"
    let cls = do
            (s,_) <- readIORef sref
            NS.close s
        send bss = void $ do
            (s,_) <- readIORef sref
            NSB.sendMany s bss
        recv = recvServer mysa q sref
        setup = do
            conn <- serverConnection conf ver myCID peerCID oCID logAction send recv cls
            setTokenManager conn $ tokenMgr route
            setRetried conn retried
            tid0 <- forkIO $ sender   conn
            tid1 <- forkIO $ receiver conn
            tid2 <- forkIO $ resender conn
            setThreadIds conn [tid0,tid1,tid2]
            setMainThreadId conn mainThreadId
            handshakeServer conf oCID conn `E.onException` clearThreads conn
            setRegister conn register unregister
            register myCID
            setConnectionOpen conn
            return conn
    setup `E.onException` cls
  where
    -- fixme: translate all exceptions to QUICError
    tlserr e = E.throwIO $ HandshakeFailed $ show $ errorToAlertDescription e

-- | Stopping the main thread of the server.
stopQUICServer :: Connection -> IO ()
stopQUICServer conn = getMainThreadId conn >>= killThread

----------------------------------------------------------------

close :: Connection -> IO ()
close conn = do
    unless (isClient conn) $ do
        unregister <- getUnregister conn
        unregister $ myCID conn
    let frames = [ConnectionCloseQUIC NoError 0 ""]
    putOutput conn $ OutControl RTT1Level frames
    setCloseSent conn
    void $ timeout 100000 $ waitClosed conn -- fixme: timeout
    clearThreads conn
    -- close the socket after threads reading/writing the socket die.
    connClose conn
