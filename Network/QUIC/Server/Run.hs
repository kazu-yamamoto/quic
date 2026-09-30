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
run conf server = do
    labelMe "QUIC run"
    stvar <- newTVarIO Running
    -- Outside handleLogUnit on purpose.  If the addresses cannot be bound
    -- there is no server, and that is the caller's business: swallowing it
    -- returned from 'run' as if all were well, having never reached
    -- onServerReady, and left anyone waiting on that hook waiting for good.
    -- An IOSpec run wedged for two and a half days that way, on a port the
    -- previous test had not finished releasing.
    E.bracket (setup stvar) teardown $ \(_, _, _) -> handleLogUnit debugLog $ do
        onServerReady $ scHooks conf
        atomically $ do
            st <- readTVar stvar
            check $ st == Stopped
  where
    debugLog _msg = return ()
    setup stvar = do
        dispatch <- newDispatch conf
        let forkConn acc = void $ forkIO (runServer conf server dispatch stvar acc)
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
runWithSockets ssas conf server = do
    labelMe "QUIC runWithSockets"
    stvar <- newTVarIO Running
    -- As in 'run'.
    E.bracket (setup stvar) teardown $ \(_, _) -> handleLogUnit debugLog $ do
        onServerReady $ scHooks conf
        atomically $ do
            st <- readTVar stvar
            check $ st == Stopped
  where
    debugLog _msg = return ()
    setup stvar = do
        dispatch <- newDispatch conf
        let forkConn acc = void $ forkIO (runServer conf server dispatch stvar acc)
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
                    mainDone conn
                ldcc = connLDCC conn
            -- Each says why it ended, as the sender and the receiver
            -- already did.  'concurrently_' cancels the others as soon as one
            -- of them fails, so the one that did not end in AsyncCancelled is
            -- the one that ended the connection -- and it was these four that
            -- said nothing, leaving a log of two cancelled threads and no
            -- reason anywhere.
            --
            -- Being cancelled is not worth a line: the sender and the
            -- receiver already say when the connection is taken down from
            -- outside, and everything else follows them.
            let named nm act =
                    act `E.catch` \e -> do
                        case E.fromException e of
                            Just AsyncCancelled -> return ()
                            Nothing -> connDebugLog conn $ "debug: " <> nm <> ": " <> bhow e
                        E.throwIO e
            let s1 = labelMe "handshaker" >> named "handshaker" handshaker
                s2 = labelMe "sender" >> sender conn
                s3 = labelMe "receiver" >> receiver conn
                s4 = labelMe "resender" >> named "resender" (resender ldcc)
                s5 = labelMe "ldccTimer" >> named "ldccTimer" (ldccTimer ldcc)
                s6 = labelMe "QUIC server" >> named "server" server
                c1 = labelMe "concurrently1" >> concurrently_ s1 s2
                c2 = labelMe "concurrently2" >> concurrently_ c1 s3
                c3 = labelMe "concurrently3" >> concurrently_ c2 s4
                c4 = labelMe "concurrently4" >> concurrently_ c3 s5
                -- Telling the peer here, and not below, because here is the
                -- one place where it can be done at all: the nested
                -- 'concurrently_'s above have waited for every protocol
                -- thread, so the encode buffer is ours alone -- it is shared
                -- with the sender -- and the application is still running, so
                -- nothing has begun waiting for it yet.
                --
                -- Below, after 'runThreads', is too late.  The
                -- 'concurrently_' on this line cancels the application when
                -- the protocol threads fail and then waits for it, under
                -- 'uninterruptibleMask_', for as long as it takes to unwind.
                -- The CONNECTION_CLOSE waited with it, and a peer told
                -- nothing waits out its own idle timeout: seen against an
                -- HTTP/3 server whose application was slow to die just as the
                -- handshake finished, where a transport error the server had
                -- raised correctly never reached the client at all.
                --
                -- 'closure' is said once; it rethrows, and the call below
                -- finds the peer already told.
                tellThenRaise act =
                    act `E.catch` \(e :: E.SomeException) -> do
                        sendFinal conn
                        setConnectionClosed conn
                        closure conn ldcc (Left e)
                c5 =
                    labelMe "concurrently5"
                        >> concurrently_
                            (tellThenRaise (c4 `E.catch` \(_ :: InternalControl) -> return ()))
                            s6
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
    -- Say why the connection ended.  This used to discard it, so a server
    -- connection that died of anything 'closure' does not turn into a
    -- CONNECTION_CLOSE -- which is to say anything but the four it names --
    -- went without a word to the peer and without a word in the log.  The
    -- peer talks on to a connection that is gone until the dispatcher, a
    -- second later once the connection IDs are unregistered, answers it with
    -- a Stateless Reset.
    debugLog conn msg = connDebugLog conn $ "runServer: " <> msg

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
    connRecvDatagramQ <- newTQueueIO
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
            connRecvDatagramQ
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
    pathInfo <- getPathInfo conn
    cryptoToken <- generateToken ver scTicketLifetime $ peerSockAddr pathInfo
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
