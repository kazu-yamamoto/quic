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
import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Network.Socket as NS

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
run conf server = handleLogUnit debugLog $ do
    labelMe "QUIC run"
    stvar <- newTVarIO Running
    E.bracket (setup stvar) teardown $ \(_, _, _) -> do
        onServerReady $ scHooks conf
        atomically $ do
            st <- readTVar stvar
            check $ st == Stopped
  where
    debugLog _msg = return ()
    setup stvar = do
        dispatch <- newDispatch conf
        let forkConn acc = void $ forkIO (runServer conf server dispatch stvar acc)
        -- fixme: the case where sockets cannot be created.
        ssas <- mapM serverSocket $ scAddresses conf
        tids <- mapM (runDispatcher dispatch conf stvar forkConn) ssas
        return (dispatch, tids, ssas)
    teardown (dispatch, tids, ssas) = do
        clearDispatch dispatch
        mapM_ killThread tids
        mapM_ NS.close ssas

-- | Running a QUIC server.
--   The action is executed with a new connection
--   in a new lightweight thread.
runWithSockets :: [NS.Socket] -> ServerConfig -> (Connection -> IO ()) -> IO ()
runWithSockets ssas conf server = handleLogUnit debugLog $ do
    labelMe "QUIC runWithSockets"
    stvar <- newTVarIO Running
    E.bracket (setup stvar) teardown $ \(_, _) -> do
        onServerReady $ scHooks conf
        atomically $ do
            st <- readTVar stvar
            check $ st == Stopped
  where
    debugLog _msg = return ()
    setup stvar = do
        dispatch <- newDispatch conf
        let forkConn acc = void $ forkIO (runServer conf server dispatch stvar acc)
        -- fixme: the case where sockets cannot be created.
        tids <- mapM (runDispatcher dispatch conf stvar forkConn) ssas
        return (dispatch, tids)
    teardown (dispatch, tids) = do
        clearDispatch dispatch
        mapM_ killThread tids

-- Typically, ConnectionIsClosed breaks acceptStream.
-- And the exception should be ignored.
runServer
    :: ServerConfig
    -> (Connection -> IO ())
    -> Dispatch
    -> TVar ServerState
    -> Accept
    -> IO ()
runServer conf server0 dispatch stvar acc = do
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
            let srt = genStatelessReset dispatch $ fromJust $ initSrcCID myAuthCIDs
            handshaker <- handshakeServer conf' conn myAuthCIDs srt
            let server = do
                    wait1RTTReady conn
                    afterHandshakeServer conf conn
                    server0 conn
                    atomically $ writeTVar (connDone conn) True
                ldcc = connLDCC conn
            let s1 = labelMe "handshaker" >> handshaker
                s2 = labelMe "sender" >> sender conn
                s3 = labelMe "receiver" >> receiver conn
                s4 = labelMe "resender" >> resender ldcc
                s5 = labelMe "ldccTimer" >> ldccTimer ldcc
                s6 = labelMe "QUIC server" >> server
                c1 = labelMe "concurrently1" >> concurrently_ s1 s2
                c2 = labelMe "concurrently2" >> concurrently_ c1 s3
                c3 = labelMe "concurrently3" >> concurrently_ c2 s4
                c4 = labelMe "concurrently4" >> concurrently_ c3 s5
                c5 = labelMe "concurrently5" >> concurrently_ c4 s6
                runThreads = c5
            ex <- E.try runThreads
            sendFinal conn
            setConnectionClosed conn
            closure conn ldcc ex
  where
    open = createServerConnection conf dispatch acc stvar
    clse connRes = do
        let conn = connResConnection connRes
        setDead conn
        freeResources conn
    debugLog _conn _msg = return ()

createServerConnection
    :: ServerConfig
    -> Dispatch
    -> Accept
    -> TVar ServerState
    -> IO ConnRes
createServerConnection conf@ServerConfig{..} dispatch Accept{..} stvar = do
    sref <- newIORef accMySocket
    pathInfo <- newPathInfo accPeerSockAddr
    piref <- newIORef $ PeerInfo pathInfo Nothing
    let send buf siz = void $ do
            sock <- readIORef sref
            PeerInfo pinfo _ <- readIORef piref
            NS.sendBufTo sock buf siz $ peerSockAddr pinfo
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
            (genStatelessReset dispatch)
    addResource conn qclean
    addResource conn dclean
    let cid = fromMaybe ocid $ retrySrcCID accMyAuthCIDs
        ver = chosenVersion accVersionInfo
    initializeCoder conn InitialLevel $ initialSecrets ver cid
    setupCryptoStreams conn -- fixme: cleanup
    let peersa = accPeerSockAddr
        -- RFC9000 \S14.2
        -- "In the absence of these mechanisms, QUIC endpoints SHOULD
        -- NOT send datagrams larger than the smallest allowed maximum
        -- datagram size."
        --
        -- Thus use 1200 bytes for minimum packet size.
        pktSiz =
            (defaultQUICPacketSize `max` accPacketSize)
                `min` maximumPacketSize peersa
    setMaxPacketSize conn pktSiz
    setInitialCongestionWindow (connLDCC conn) pktSiz
    debugLog $ "Packet size: " <> bhow pktSiz <> " (" <> bhow accPacketSize <> ")"
    when accAddressValidated $ setAddressValidated pathInfo
    --
    let retried = isJust $ retrySrcCID accMyAuthCIDs
    when retried $ do
        qlogRecvInitial conn
        qlogSentRetry conn
    --
    let mgr = tokenMgr dispatch
    setTokenManager conn mgr
    --
    setStopServer conn $ atomically $ writeTVar stvar Stopped
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
stop conn = do
    action <- getStopServer conn
    action
