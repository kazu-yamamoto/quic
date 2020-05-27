{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Run where

import Control.Concurrent
import qualified Control.Exception as E
import Data.IORef
import Data.X509 (CertificateChain)
import Foreign.Marshal.Alloc (free)
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB
import Network.TLS hiding (Version, HandshakeFailed)

import Network.QUIC.Client
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Handshake
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Receiver
import Network.QUIC.Sender
import Network.QUIC.Server
import Network.QUIC.Socket
import Network.QUIC.Timeout
import Network.QUIC.Types

----------------------------------------------------------------

-- | Running a QUIC client.
runQUICClient :: ClientConfig -> (Connection -> IO a) -> IO a
runQUICClient conf client = do
    when (null $ confVersions $ ccConfig conf) $ E.throwIO NoVersionIsSpecified
    E.bracket (forkIO timeouter)
              killThread
              (\_ -> E.bracket (connect conf) close client)

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
        (conn,send,recv,cls,qlogger,myAuthCIDs) <- createClientConnection conf ver
        handshakeClientConnection conf conn send recv qlogger myAuthCIDs `E.onException` cls
        return conn
    check se
      | Just (NextVersion ver)   <- E.fromException se = Right ver
      | Just (e :: QUICError)    <- E.fromException se = Left e
      | Just (e :: TLSException) <- E.fromException se = Left (HandshakeFailed $ show e)
      | otherwise = Left $ BadThingHappen se

createClientConnection :: ClientConfig -> Version
                       -> IO (Connection, SendMany, Receive, Close, IO (), AuthCIDs)
createClientConnection conf@ClientConfig{..} ver = do
    s0 <- udpClientConnectedSocket ccServerName ccPortName
    q <- newRecvQ
    sref <- newIORef (s0,q)
    let cls = do
            (s,_) <- readIORef sref
            NS.close s
        send bss = do
            (s,_) <- readIORef sref
            void $ NSB.sendMany s bss
        recv = recvClient q
    myCID   <- newCID
    peerCID <- newCID
    qq <- newQlogQ
    let debugLog msg = confDebugLog ccConfig peerCID (msg ++ "\n") `E.catch` ignore

        qLog msg = writeQlogQ qq msg
        qlogger = newQlogger qq "client" (show peerCID) $ confQLog ccConfig peerCID
    debugLog $ "Original CID: " ++ show peerCID
    let myAuthCIDs   = defaultAuthCIDs { initSrcCID = Just myCID }
        peerAuthCIDs = defaultAuthCIDs { initSrcCID = Just peerCID, origDstCID = Just peerCID }
    conn <- clientConnection conf ver myAuthCIDs peerAuthCIDs debugLog qLog cls sref
    setupCryptoStreams conn -- fixme: cleanup
    --
    mytid <- myThreadId
    --
    void $ forkIO $ readerClient mytid (confVersions ccConfig) s0 q conn -- dies when s0 is closed.
    return (conn,send,recv,cls,qlogger,myAuthCIDs)

handshakeClientConnection :: ClientConfig -> Connection -> SendMany -> Receive -> IO () -> AuthCIDs -> IO ()
handshakeClientConnection conf@ClientConfig{..} conn send recv qlogger myAuthCIDs = do
    setToken conn $ resumptionToken ccResumption
    tid0 <- forkIO $ sender   conn send
    tid1 <- forkIO $ receiver conn recv
    tid2 <- forkIO $ resender conn
    tid3 <- forkIO qlogger
    setThreadIds conn [tid0,tid1,tid2,tid3]
    handshakeClient conf conn myAuthCIDs `E.onException` clearThreads conn

----------------------------------------------------------------

-- | Running a QUIC server.
--   The action is executed with a new connection
--   in a new lightweight thread.
runQUICServer :: ServerConfig -> (Connection -> IO ()) -> IO ()
runQUICServer conf server = handleLog debugLog $ do
    mainThreadId <- myThreadId
    E.bracket setup teardown $ \(dispatch,_) -> forever $ do
        acc <- accept dispatch
        let create = do
                (conn,send,recv,cls,qlogger, myAuthCIDs) <- createServerConnection conf dispatch acc mainThreadId
                handshakeServerConnection conf conn send recv qlogger myAuthCIDs `E.onException` cls
                return conn
        void $ forkIO $ E.bracket create close server
  where
    debugLog msg = putStrLn ("runQUICServer: " ++ msg)
    setup = do
        dispatch <- newDispatch
        -- fixme: the case where sockets cannot be created.
        ssas <- mapM  udpServerListenSocket $ scAddresses conf
        tids <- mapM (runDispatcher dispatch conf) ssas
        ttid <- forkIO timeouter
        return (dispatch, ttid:tids)
    teardown (dispatch, tids) = do
        clearDispatch dispatch
        mapM_ killThread tids

createServerConnection :: ServerConfig -> Dispatch -> Accept -> ThreadId
                       -> IO (Connection, SendMany, Receive, Close, IO (), AuthCIDs)
createServerConnection conf dispatch acc mainThreadId = do
    let Accept ver myAuthCIDs peerAuthCIDs mysa peersa0 q register unregister = acc
    s0 <- udpServerConnectedSocket mysa peersa0
    sref <- newIORef (s0,q)
    let cls = do
            (s,_) <- readIORef sref
            NS.close s
        send bss = void $ do
            (s,_) <- readIORef sref
            NSB.sendMany s bss
        recv = recvServer q
    let Just myCID = initSrcCID myAuthCIDs
        Just ocid  = origDstCID myAuthCIDs
    qq <- newQlogQ
    let sconf = scConfig conf
        debugLog msg = confDebugLog sconf ocid (msg ++ "\n") `E.catch` ignore
        qLog msg = writeQlogQ qq msg
        qlogger = newQlogger qq "server" (show ocid) $ confQLog sconf ocid
    debugLog $ "Original CID: " ++ show ocid
    conn <- serverConnection conf ver myAuthCIDs peerAuthCIDs debugLog qLog cls sref
    setupCryptoStreams conn -- fixme: cleanup
    --
    let retried = isJust $ retrySrcCID myAuthCIDs
    when retried $ do
        qlogRecvInitial conn
        qlogSentRetry conn
    --
    let mgr = tokenMgr dispatch
    setTokenManager conn mgr
    --
    setMainThreadId conn mainThreadId
    --
    setRegister conn register unregister
    register myCID conn
    --
    void $ forkIO $ readerServer s0 q debugLog -- dies when s0 is closed.
    return (conn, send, recv, cls, qlogger, myAuthCIDs)

handshakeServerConnection :: ServerConfig -> Connection -> SendMany -> Receive -> IO () -> AuthCIDs -> IO ()
handshakeServerConnection conf@ServerConfig{..} conn send recv qlogger myAuthCIDs = do
    tid0 <- forkIO $ sender conn send
    tid1 <- forkIO $ receiver conn recv
    tid2 <- forkIO $ resender conn
    tid3 <- forkIO qlogger
    setThreadIds conn [tid0,tid1,tid2,tid3]
    handshakeServer conf conn myAuthCIDs `E.onException` clearThreads conn
    --
    cidInfo <- getNewMyCID conn
    register <- getRegister conn
    register (cidInfoCID cidInfo) conn
    --
    cryptoToken <- generateToken =<< getVersion conn
    mgr <- getTokenManager conn
    token <- encryptToken mgr cryptoToken
    let ncid = NewConnectionID cidInfo 0
    let frames = [NewToken token,ncid]
    putOutput conn $ OutControl RTT1Level frames

-- | Stopping the main thread of the server.
stopQUICServer :: Connection -> IO ()
stopQUICServer conn = getMainThreadId conn >>= killThread

----------------------------------------------------------------

close :: Connection -> IO ()
close conn = do
    when (isServer conn) $ do
        unregister <- getUnregister conn
        myCIDs <- getMyCIDs conn
        mapM_ unregister myCIDs
    let frames = [ConnectionCloseQUIC NoError 0 ""]
    putOutput conn $ OutControl RTT1Level frames
    setCloseSent conn
    void $ timeout 100000 $ waitClosed conn -- fixme: timeout
    when (isServer conn) $ do
        unregister <- getUnregister conn
        myCIDs <- getMyCIDs conn
        mapM_ unregister myCIDs
    killHandshaker conn
    clearThreads conn
    -- close the socket after threads reading/writing the socket die.
    closeSockets conn
    free $ headerBuffer conn
    free $ payloadBuffer conn

----------------------------------------------------------------

ignore :: E.SomeException -> IO ()
ignore _ = return ()

clientCertificateChain :: Connection -> IO (Maybe CertificateChain)
clientCertificateChain conn
  | isClient conn = return Nothing
  | otherwise     = getCertificateChain conn
