{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Server.Run (
    run,
    runWithSockets,
    stop,
) where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import qualified Network.Socket as NS
import System.Log.FastLogger

import Network.QUIC.Closer
import Network.QUIC.Common
import Network.QUIC.Config
import Network.QUIC.Connection
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
import Network.QUIC.Server.Reader
import Network.QUIC.Socket
import Network.QUIC.Types

----------------------------------------------------------------

-- | Running a QUIC server.
--   The action is executed with a new connection
--   in a new lightweight thread.
run :: ServerConfig -> (Connection -> IO ()) -> IO ()
run conf server = NS.withSocketsDo $ handleLogUnit debugLog $ do
    labelMe "QUIC run"
    baseThreadId <- myThreadId
    E.bracket setup teardown $ \(dispatch, _, _) -> do
        onServerReady $ scHooks conf
        forever $ do
            acc <- accept dispatch
            void $ forkIO (runServer conf server dispatch baseThreadId acc)
  where
    doDebug = isJust $ scDebugLog conf
    debugLog msg
        | doDebug = stdoutLogger ("run: " <> msg)
        | otherwise = return ()
    setup = do
        dispatch <- newDispatch conf
        -- fixme: the case where sockets cannot be created.
        ssas <- mapM serverSocket $ scAddresses conf
        tids <- mapM (runDispatcher dispatch conf) ssas
        return (dispatch, tids, ssas)
    teardown (dispatch, tids, ssas) = do
        clearDispatch dispatch
        mapM_ killThread tids
        mapM_ NS.close ssas

-- | Running a QUIC server.
--   The action is executed with a new connection
--   in a new lightweight thread.
runWithSockets :: [NS.Socket] -> ServerConfig -> (Connection -> IO ()) -> IO ()
runWithSockets ssas conf server = NS.withSocketsDo $ handleLogUnit debugLog $ do
    labelMe "QUIC runWithSockets"
    baseThreadId <- myThreadId
    E.bracket setup teardown $ \(dispatch, _) -> do
        onServerReady $ scHooks conf
        forever $ do
            acc <- accept dispatch
            void $ forkIO (runServer conf server dispatch baseThreadId acc)
  where
    doDebug = isJust $ scDebugLog conf
    debugLog msg
        | doDebug = stdoutLogger ("run: " <> msg)
        | otherwise = return ()
    setup = do
        dispatch <- newDispatch conf
        -- fixme: the case where sockets cannot be created.
        tids <- mapM (runDispatcher dispatch conf) ssas
        return (dispatch, tids)
    teardown (dispatch, tids) = do
        clearDispatch dispatch
        mapM_ killThread tids

-- Typically, ConnectionIsClosed breaks acceptStream.
-- And the exception should be ignored.
runServer
    :: ServerConfig -> (Connection -> IO ()) -> Dispatch -> ThreadId -> Accept -> IO ()
runServer conf server0 dispatch baseThreadId acc = do
    labelMe "QUIC runServer"
    E.bracket open clse $ \(ConnRes conn myAuthCIDs _reader) ->
        handleLogUnit (debugLog conn) $ do
            let conf' =
                    conf
                        { scParameters =
                            (scParameters conf)
                                { versionInformation = Just $ accVersionInfo acc
                                }
                        }
            handshaker <- handshakeServer conf' conn myAuthCIDs
            let server = do
                    wait1RTTReady conn
                    afterHandshakeServer conf conn
                    server0 conn
                ldcc = connLDCC conn
                supporters =
                    foldr1
                        concurrently_
                        [ handshaker
                        , sender conn
                        , receiver conn
                        , resender ldcc
                        , ldccTimer ldcc
                        ]
                runThreads = do
                    er <- race supporters server
                    case er of
                        Left () -> E.throwIO MustNotReached
                        Right r -> return r
            ex <- E.try runThreads
            sendFinal conn
            closure conn ldcc ex
  where
    open = createServerConnection conf dispatch acc baseThreadId
    clse connRes = do
        let conn = connResConnection connRes
        setDead conn
        freeResources conn
    debugLog conn msg = do
        connDebugLog conn ("runServer: " <> msg)
        qlogDebug conn $ Debug $ toLogStr msg

createServerConnection
    :: ServerConfig
    -> Dispatch
    -> Accept
    -> ThreadId
    -> IO ConnRes
createServerConnection conf@ServerConfig{..} dispatch Accept{..} baseThreadId = do
    sref <- newIORef accMySocket
    piref <- newIORef accPeerInfo
    let send buf siz = void $ do
            sock <- readIORef sref
            PeerInfo sa cmsgs <- readIORef piref
            NS.sendBufMsg sock sa [(buf, siz)] cmsgs 0
        recv = recvServer accRecvQ
    let myCID = fromJust $ initSrcCID accMyAuthCIDs
        ocid = fromJust $ origDstCID accMyAuthCIDs
    (qLog, qclean) <- dirQLogger scQLog accTime ocid "server"
    (debugLog, dclean) <- dirDebugLogger scDebugLog ocid
    debugLog $ "Original CID: " <> bhow ocid
    conn <-
        serverConnection
            conf
            accVersionInfo
            accMyAuthCIDs
            accPeerAuthCIDs
            debugLog
            qLog
            scHooks
            sref
            piref
            accRecvQ
            send
            recv
    addResource conn qclean
    addResource conn dclean
    let cid = fromMaybe ocid $ retrySrcCID accMyAuthCIDs
        ver = chosenVersion accVersionInfo
    initializeCoder conn InitialLevel $ initialSecrets ver cid
    setupCryptoStreams conn -- fixme: cleanup
    let PeerInfo peersa _ = accPeerInfo
        pktSiz =
            (defaultPacketSize peersa `max` accPacketSize)
                `min` maximumPacketSize peersa
    setMaxPacketSize conn pktSiz
    setInitialCongestionWindow (connLDCC conn) pktSiz
    debugLog $ "Packet size: " <> bhow pktSiz <> " (" <> bhow accPacketSize <> ")"
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
    setBaseThreadId conn baseThreadId
    --
    setRegister conn accRegister accUnregister
    accRegister myCID conn
    addResource conn $ do
        myCIDs <- getMyCIDs conn
        mapM_ accUnregister myCIDs

    --
    return $ ConnRes conn accMyAuthCIDs undefined

afterHandshakeServer :: ServerConfig -> Connection -> IO ()
afterHandshakeServer ServerConfig{..} conn = handleLogT logAction $ do
    --
    cidInfo <- getNewMyCID conn
    register <- getRegister conn
    register (cidInfoCID cidInfo) conn
    --
    ver <- getVersion conn
    cryptoToken <- generateToken ver scTicketLifetime
    mgr <- getTokenManager conn
    token <- encryptToken mgr cryptoToken
    let ncid = NewConnectionID cidInfo 0
    sendFrames conn RTT1Level [NewToken token, ncid, HandshakeDone]
  where
    logAction msg = connDebugLog conn $ "afterHandshakeServer: " <> msg

-- | Stopping the base thread of the server.
stop :: Connection -> IO ()
stop conn = getBaseThreadId conn >>= killThread
