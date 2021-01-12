{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Run (
    runQUICClient
  , runQUICServer
  , stopQUICServer
  , clientCertificateChain
  ) where

import Control.Concurrent
import qualified Control.Exception as E
import Data.X509 (CertificateChain)
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB

import Network.QUIC.Client
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Exception
import Network.QUIC.Handshake
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.QLogger
import Network.QUIC.Receiver
import Network.QUIC.Recovery
import Network.QUIC.Sender
import Network.QUIC.Server
import Network.QUIC.Socket
import Network.QUIC.TLS
import Network.QUIC.Timeout
import Network.QUIC.Types

----------------------------------------------------------------

data ConnRes = ConnRes Connection SendMany Receive AuthCIDs

connResConnection :: ConnRes -> Connection
connResConnection (ConnRes conn _ _ _) = conn

----------------------------------------------------------------

-- | Running a QUIC client.
runQUICClient :: ClientConfig -> (Connection -> IO a) -> IO a
runQUICClient conf client = do
    when (null $ confVersions $ ccConfig conf) $ E.throwIO NoVersionIsSpecified
    E.bracket (forkIO timeouter)
              killThread
              (\_ -> E.bracket (connect conf) freeResources clientAndClose)
  where
    clientAndClose conn = client conn `E.finally` do
        sent <- isCloseSent conn
        unless sent $ sendConnectionClose conn $ ConnectionClose NoError 0 ""
        threadDelay 100000

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
    connect' ver = E.bracketOnError open clse body
      where
        open = createClientConnection conf ver
        clse connRes = do
            let conn = connResConnection connRes
            sendConnectionClose conn $ ConnectionClose NoError 0 ""
            threadDelay 100000
            freeResources conn
        body = handshakeClientConnection conf
    check se
      | Just (NextVersion ver)    <- E.fromException se = Right ver
      | Just (e :: QUICException) <- E.fromException se = Left e
      | otherwise                                       = Left $ BadThingHappen se

createClientConnection :: ClientConfig -> Version -> IO ConnRes
createClientConnection conf@ClientConfig{..} ver = do
    (s0,sa0) <- udpClientConnectedSocket ccServerName ccPortName
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
    now <- getTimeMicrosecond
    (qLog, qclean) <- dirQLogger (confQLog ccConfig) now peerCID "client"
    let debugLog msg | ccDebugLog = stdoutLogger msg
                     | otherwise  = return ()
    debugLog $ "Original CID: " <> bhow peerCID
    let myAuthCIDs   = defaultAuthCIDs { initSrcCID = Just myCID }
        peerAuthCIDs = defaultAuthCIDs { initSrcCID = Just peerCID, origDstCID = Just peerCID }
        hooks = confHooks ccConfig
    conn <- clientConnection conf ver myAuthCIDs peerAuthCIDs debugLog qLog hooks sref
    addResource conn cls
    addResource conn qclean
    initializeCoder conn InitialLevel $ initialSecrets ver peerCID
    setupCryptoStreams conn -- fixme: cleanup
    let pktSiz0 = fromMaybe 0 ccPacketSize
        pktSiz = (defaultPacketSize sa0 `max` pktSiz0) `min` maximumPacketSize sa0
    setMaxPacketSize conn pktSiz
    setInitialCongestionWindow (connLDCC conn) pktSiz
    setAddressValidated conn
    --
    mytid <- myThreadId
    --
    void $ forkIO $ readerClient mytid (confVersions ccConfig) s0 q conn -- dies when s0 is closed.
    return $ ConnRes conn send recv myAuthCIDs

handshakeClientConnection :: ClientConfig -> ConnRes -> IO Connection
handshakeClientConnection conf@ClientConfig{..} (ConnRes conn send recv myAuthCIDs) = handleLogE logAction $ do
    setToken conn $ resumptionToken ccResumption
    tid0 <- forkIO $ sender   conn send
    tid1 <- forkIO $ receiver conn recv
    tid2 <- forkIO $ resender $ connLDCC conn
    tid3 <- forkIO $ ldccTimer $ connLDCC conn
    addThreadIdResource conn tid0
    addThreadIdResource conn tid1
    addThreadIdResource conn tid2
    addThreadIdResource conn tid3
    handshakeClient conf conn myAuthCIDs
    addResource conn $ killHandshaker conn
    return conn
  where
    logAction msg = connDebugLog conn $ "handshakeClientConnection: " <> msg

----------------------------------------------------------------

-- | Running a QUIC server.
--   The action is executed with a new connection
--   in a new lightweight thread.
runQUICServer :: ServerConfig -> (Connection -> IO ()) -> IO ()
runQUICServer conf server = handleLog debugLog $ do
    mainThreadId <- myThreadId
    E.bracket setup teardown $ \(dispatch,_) -> forever $ do
        acc <- accept dispatch
        let create = E.bracketOnError open clse body
             where
               open = createServerConnection conf dispatch acc mainThreadId
               clse = freeResources . connResConnection
               body = handshakeServerConnection conf
        -- Typically, ConnectionIsClosed breaks acceptStream.
        -- And the exception should be ignored.
        void $ forkIO (handleLog debugLog $ E.bracket create freeResources serverAndClose)
  where
    serverAndClose conn = do
        server conn
        sendConnectionClose conn $ ConnectionClose NoError 0 ""
        void $ timeout (Microseconds 100000) $ waitClosed conn -- fixme: timeout
    debugLog msg = stdoutLogger ("runQUICServer: " <> msg)
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
                       -> IO ConnRes
createServerConnection conf@ServerConfig{..} dispatch Accept{..} mainThreadId = do
    s0 <- udpServerConnectedSocket accMySockAddr accPeerSockAddr
    sref <- newIORef (s0, accRecvQ)
    let cls = do
            (s,_) <- readIORef sref
            NS.close s
        send bss = void $ do
            (s,_) <- readIORef sref
            NSB.sendMany s bss
        recv = recvServer accRecvQ
    let Just myCID = initSrcCID accMyAuthCIDs
        Just ocid  = origDstCID accMyAuthCIDs
    (qLog, qclean)     <- dirQLogger (confQLog scConfig) accTime ocid "server"
    (debugLog, dclean) <- dirDebugLogger scDebugLog ocid
    let hooks = confHooks scConfig
    debugLog $ "Original CID: " <> bhow ocid
    conn <- serverConnection conf accVersion accMyAuthCIDs accPeerAuthCIDs debugLog qLog hooks sref
    addResource conn cls
    addResource conn qclean
    addResource conn dclean
    let cid = fromMaybe ocid $ retrySrcCID accMyAuthCIDs
    initializeCoder conn InitialLevel $ initialSecrets accVersion cid
    setupCryptoStreams conn -- fixme: cleanup
    let pktSiz = (defaultPacketSize accMySockAddr `max` accPacketSize) `min` maximumPacketSize accMySockAddr
    setMaxPacketSize conn pktSiz
    setInitialCongestionWindow (connLDCC conn) pktSiz
    debugLog $ "Packet size: " <> bhow pktSiz <> " (" <> bhow accPacketSize <> ")"
    addRxBytes conn accPacketSize
    when accAddressValidated $ setAddressValidated conn
    --
    let retried = isJust $ retrySrcCID accMyAuthCIDs
    when retried $ do
        qlogRecvInitial conn
        qlogSentRetry conn
    --
    let mgr = tokenMgr dispatch
    setTokenManager conn mgr
    --
    setMainThreadId conn mainThreadId
    --
    setRegister conn accRegister accUnregister
    accRegister myCID conn
    addResource conn $ do
        myCIDs <- getMyCIDs conn
        mapM_ accUnregister myCIDs
    --
    void $ forkIO $ readerServer s0 accRecvQ conn -- dies when s0 is closed.
    return $ ConnRes conn send recv accMyAuthCIDs

handshakeServerConnection :: ServerConfig -> ConnRes -> IO Connection
handshakeServerConnection conf (ConnRes conn send recv myAuthCIDs) = handleLogE logAction $ do
    tid0 <- forkIO $ sender conn send
    tid1 <- forkIO $ receiver conn recv
    tid2 <- forkIO $ resender $ connLDCC conn
    tid3 <- forkIO $ ldccTimer $ connLDCC conn
    addThreadIdResource conn tid0
    addThreadIdResource conn tid1
    addThreadIdResource conn tid2
    addThreadIdResource conn tid3
    handshakeServer conf conn myAuthCIDs
    --
    cidInfo <- getNewMyCID conn
    register <- getRegister conn
    register (cidInfoCID cidInfo) conn
    --
    cryptoToken <- generateToken =<< getVersion conn
    mgr <- getTokenManager conn
    token <- encryptToken mgr cryptoToken
    let ncid = NewConnectionID cidInfo 0
    let frames = [NewToken token,ncid,HandshakeDone]
    putOutput conn $ OutControl RTT1Level frames
    addResource conn $ killHandshaker conn
    return conn
  where
    logAction msg = connDebugLog conn $ "handshakeServerConnection: " <> msg

-- | Stopping the main thread of the server.
stopQUICServer :: Connection -> IO ()
stopQUICServer conn = getMainThreadId conn >>= killThread

----------------------------------------------------------------

-- | Getting a certificate chain.
clientCertificateChain :: Connection -> IO (Maybe CertificateChain)
clientCertificateChain conn
  | isClient conn = return Nothing
  | otherwise     = getCertificateChain conn

defaultPacketSize :: NS.SockAddr -> Int
defaultPacketSize NS.SockAddrInet6{} = defaultQUICPacketSizeForIPv6
defaultPacketSize _                  = defaultQUICPacketSizeForIPv4

maximumPacketSize :: NS.SockAddr -> Int
maximumPacketSize NS.SockAddrInet6{} = 1500 - 40 - 8 -- fixme
maximumPacketSize _                  = 1500 - 20 - 8 -- fixme
