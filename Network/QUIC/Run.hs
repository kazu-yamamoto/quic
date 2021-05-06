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
import Control.Concurrent.Async
import qualified Control.Exception as E
import Data.X509 (CertificateChain)
import qualified Network.Socket as NS
import System.Log.FastLogger

import Network.QUIC.Client
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Crypto
import Network.QUIC.Exception
import Network.QUIC.Handshake
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.QLogger
import Network.QUIC.Qlog
import Network.QUIC.Receiver
import Network.QUIC.Recovery
import Network.QUIC.Sender
import Network.QUIC.Server
import Network.QUIC.Socket
import Network.QUIC.Types

----------------------------------------------------------------

data ConnRes = ConnRes Connection SendBuf Receive AuthCIDs (IO ())

connResConnection :: ConnRes -> Connection
connResConnection (ConnRes conn _ _ _ _) = conn

----------------------------------------------------------------

-- | Running a QUIC client.
runQUICClient :: ClientConfig -> (Connection -> IO a) -> IO a
-- Don't use handleLogUnit here because of a return value.
runQUICClient conf client = case confVersions $ ccConfig conf of
  []     -> E.throwIO NoVersionIsSpecified
  ver1:_ -> do
      ex <- E.try $ runClient conf client ver1
      case ex of
        Right v                     -> return v
        Left se@(E.SomeException e)
          | Just (NextVersion ver2) <- E.fromException se
                                    -> runClient conf client ver2
          | otherwise               -> E.throwIO e

runClient :: ClientConfig -> (Connection -> IO a) -> Version -> IO a
runClient conf client ver = do
    E.bracket open clse $ \(ConnRes conn send recv myAuthCIDs reader) -> do
        void $ forkIO reader -- dies when the socket is closed
        handshaker <- handshakeClient conf conn myAuthCIDs
        let cli = do
                let use0RTT = ccUse0RTT conf
                if use0RTT then
                    wait0RTTReady conn
                  else
                    wait1RTTReady conn
                setToken conn $ resumptionToken $ ccResumption conf
                client conn
            cli' = cli `E.finally` do
                sent <- isCloseSent conn
                lvl <- getEncryptionLevel conn
                unless sent $ sendCCFrameAndWait conn lvl NoError "" 0
            ldcc = connLDCC conn
            runThreads = foldr1 concurrently_ [timeouter
                                              ,handshaker
                                              ,sender   conn send
                                              ,receiver conn recv
                                              ,resender  ldcc
                                              ,ldccTimer ldcc
                                              ]
            runThreads' = race runThreads cli'
        ex <- runThreads'
        case ex of
          Left () -> E.throwIO MustNotReached
          Right x -> return x
  where
    open = createClientConnection conf ver
    clse connRes = do
        let conn = connResConnection connRes
        setDead conn
        freeResources conn

createClientConnection :: ClientConfig -> Version -> IO ConnRes
createClientConnection conf@ClientConfig{..} ver = do
    (s0,sa0) <- udpClientConnectedSocket ccServerName ccPortName
    q <- newRecvQ
    sref <- newIORef (s0,q)
    let cls = do
            (s,_) <- readIORef sref
            shutdownAndClose s
        send buf siz = do
            (s,_) <- readIORef sref
            void $ NS.sendBuf s buf siz
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
    let reader = readerClient mytid (confVersions ccConfig) s0 q conn -- dies when s0 is closed.
    return $ ConnRes conn send recv myAuthCIDs reader

----------------------------------------------------------------

-- | Running a QUIC server.
--   The action is executed with a new connection
--   in a new lightweight thread.
runQUICServer :: ServerConfig -> (Connection -> IO ()) -> IO ()
runQUICServer conf server = handleLogUnit debugLog $ do
    mainThreadId <- myThreadId
    E.bracket setup teardown $ \(dispatch,_) -> forever $ do
        acc <- accept dispatch
        void $ forkIO (runServer conf server dispatch mainThreadId acc)
  where
    debugLog msg = stdoutLogger ("runQUICServer: " <> msg)
    setup = do
        dispatch <- newDispatch
        -- fixme: the case where sockets cannot be created.
        ssas <- mapM  udpServerListenSocket $ scAddresses conf
        tids <- mapM (runDispatcher dispatch conf) ssas
        ttid <- forkIO timeouter -- fixme
        return (dispatch, ttid:tids)
    teardown (dispatch, tids) = do
        clearDispatch dispatch
        mapM_ killThread tids

-- Typically, ConnectionIsClosed breaks acceptStream.
-- And the exception should be ignored.
runServer :: ServerConfig -> (Connection -> IO ()) -> Dispatch -> ThreadId -> Accept -> IO ()
runServer conf server dispatch mainThreadId acc =
    E.bracket open clse $ \(ConnRes conn send recv myAuthCIDs reader) ->
        handleLogUnit (debugLog conn) $ do
            void $ forkIO reader -- dies when the socket is closed
            handshaker <- handshakeServer conf conn myAuthCIDs
            let svr = do
                    wait1RTTReady conn
                    afterHandshakeServer conn
                    server conn
                    sendCCFrameAndWait conn RTT1Level NoError "" 0
                ldcc = connLDCC conn
                runThreads = foldr1 concurrently_ [svr
                                                  ,handshaker
                                                  ,sender   conn send
                                                  ,receiver conn recv
                                                  ,resender  ldcc
                                                  ,ldccTimer ldcc
                                                  ]
            runThreads
  where
    open = createServerConnection conf dispatch acc mainThreadId
    clse connRes = do
        let conn = connResConnection connRes
        setDead conn
        freeResources conn
    debugLog conn msg = do
        connDebugLog conn ("runServer: " <> msg)
        qlogDebug conn $ Debug $ toLogStr msg

createServerConnection :: ServerConfig -> Dispatch -> Accept -> ThreadId
                       -> IO ConnRes
createServerConnection conf@ServerConfig{..} dispatch Accept{..} mainThreadId = do
    s0 <- udpServerConnectedSocket accMySockAddr accPeerSockAddr
    sref <- newIORef (s0, accRecvQ)
    let cls = do
            (s,_) <- readIORef sref
            shutdownAndClose s
        send buf siz = void $ do
            (s,_) <- readIORef sref
            NS.sendBuf s buf siz
        recv = recvServer accRecvQ
    let Just myCID = initSrcCID accMyAuthCIDs
        Just ocid  = origDstCID accMyAuthCIDs
    (qLog, qclean)     <- dirQLogger (confQLog scConfig) accTime ocid "server"
    (debugLog, dclean) <- dirDebugLogger scDebugLog ocid
    let hooks = confHooks scConfig
    debugLog $ "Original CID: " <> bhow ocid
    conn <- serverConnection conf accVersion accMyAuthCIDs accPeerAuthCIDs debugLog qLog hooks sref
    setSockAddrs conn (accMySockAddr,accPeerSockAddr)
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
    let reader = readerServer s0 accRecvQ conn -- dies when s0 is closed.
    return $ ConnRes conn send recv accMyAuthCIDs reader

afterHandshakeServer :: Connection -> IO ()
afterHandshakeServer conn = handleLogT logAction $ do
    --
    cidInfo <- getNewMyCID conn
    register <- getRegister conn
    register (cidInfoCID cidInfo) conn
    --
    cryptoToken <- generateToken =<< getVersion conn
    mgr <- getTokenManager conn
    token <- encryptToken mgr cryptoToken
    let ncid = NewConnectionID cidInfo 0
    sendFrames conn RTT1Level [NewToken token,ncid,HandshakeDone]
  where
    logAction msg = connDebugLog conn $ "afterHandshakeServer: " <> msg

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
