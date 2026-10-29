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
import qualified System.Timeout as T

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
    let stopNow = stopping stvar
    installShutdownHandler conf stopNow
    -- Outside handleLogUnit on purpose.  If the addresses cannot be bound
    -- there is no server, and that is the caller's business: swallowing it
    -- returned from 'run' as if all were well, having never reached
    -- onServerReady, and left anyone waiting on that hook waiting for good.
    -- An IOSpec run wedged for two and a half days that way, on a port the
    -- previous test had not finished releasing.
    E.bracket (setup stvar stopNow) (teardown stopNow) $ \_ -> handleLogUnit debugLog $ do
        onServerReady $ scHooks conf
        atomically $ do
            st <- readTVar stvar
            check $ st == Stopped
  where
    debugLog _msg = return ()
    -- 'setup' is this bracket's acquire, so 'teardown' does not run when it
    -- throws -- and it does throw: a server given two addresses whose second
    -- port is taken leaves the first socket bound and the token manager
    -- thread running, for good.  Each step frees what the steps before it
    -- took, which for a list means each element frees itself.
    setup stvar stopNow = do
        dispatch <- newDispatch conf stopNow
        let forkConn acc =
                spawnConnection dispatch $
                    runServer conf server dispatch acc
        flip E.onException (clearDispatch dispatch) $ do
            ssas <- openAll $ scAddresses conf
            runAll dispatch conf stvar forkConn ssas
                `E.onException` do
                    stopNow
                    waitNoDispatcher dispatch
                    mapM_ NS.close ssas
            return (dispatch, ssas)
    -- Telling the dispatchers, and then waiting for them.  They end where
    -- they wait, on the stop variable 'stopping' sets; nothing is thrown at
    -- them, which matters because on Windows an exception would not reach a
    -- thread blocked in a socket call anyway.
    --
    -- The waiting is what lets the sockets be closed below: a dispatcher
    -- which has returned has given up its receive, and the connections
    -- waited for after it are what send on those sockets.  Telling a thread
    -- to stop is not the same as it having stopped.
    --
    -- The usual way here is through the shutdown handler, which has already
    -- done this; doing it again is free.  The way that had not, until now,
    -- is 'run' being cancelled from outside.
    teardown :: IO () -> (Dispatch, [NS.Socket]) -> IO ()
    teardown stopNow (dispatch, ssas) = do
        stopNow
        clearDispatch dispatch
        waitNoDispatcher dispatch
        shutdownConnections conf dispatch
        mapM_ NS.close ssas
    openAll [] = return []
    openAll (a : as) =
        E.bracketOnError (serverSocket a) NS.close $ \s -> (s :) <$> openAll as

-- | Running a QUIC server.
--   The action is executed with a new connection
--   in a new lightweight thread.
runWithSockets :: [NS.Socket] -> ServerConfig -> (Connection -> IO ()) -> IO ()
runWithSockets ssas conf server = do
    labelMe "QUIC runWithSockets"
    stvar <- newTVarIO Running
    let stopNow = stopping stvar
    installShutdownHandler conf stopNow
    -- As in 'run'.
    E.bracket (setup stvar stopNow) (teardown stopNow) $ \_ -> handleLogUnit debugLog $ do
        onServerReady $ scHooks conf
        atomically $ do
            st <- readTVar stvar
            check $ st == Stopped
  where
    debugLog _msg = return ()
    -- As in 'run'.  The sockets are the caller's here, so only the token
    -- manager and the dispatchers are ours to free.
    setup stvar stopNow = do
        dispatch <- newDispatch conf stopNow
        let forkConn acc =
                spawnConnection dispatch $
                    runServer conf server dispatch acc
        flip E.onException (clearDispatch dispatch) $ do
            runAll dispatch conf stvar forkConn ssas
                `E.onException` (stopNow >> waitNoDispatcher dispatch)
            return dispatch
    -- As in 'run'.  The caller's sockets are not closed here, but the
    -- dispatchers are still waited for: the caller is free to close them
    -- the moment this returns.
    teardown :: IO () -> Dispatch -> IO ()
    teardown stopNow dispatch = do
        stopNow
        clearDispatch dispatch
        waitNoDispatcher dispatch
        shutdownConnections conf dispatch

-- | Handing the caller the action that stops this server.
--
-- 'stop' is the same action, reached through a connection; a server with no
-- connections cannot be stopped that way, and a server is at its emptiest
-- when someone wants it to stop.
--
-- Stopping closes no socket and raises nothing.  The dispatchers wait for a
-- datagram and for this at once, so they see it where they wait and end
-- there; 'run' then ends the connections and returns, and the sockets are
-- the caller's to close.  Which matters beyond being tidy: waking a thread
-- out of a wait by closing the file descriptor under it is what
-- 'closeFdWith' is for, and the IO manager that provides it is not the only
-- one there will be.
installShutdownHandler :: ServerConfig -> IO () -> IO ()
installShutdownHandler = scInstallShutdownHandler

-- | Telling this server to stop: the state the dispatchers read, and then
--   the datagram that gets them to read it.
-- The dispatchers wait on this variable and on their receive at once, so
-- setting it is all there is to stopping them: nothing has to be sent to
-- the sockets and nothing has to be thrown into the threads.
stopping :: TVar ServerState -> IO ()
stopping stvar = atomically $ writeTVar stvar Stopped

-- | Ending the connections the server still has, while the sockets are
--   still open.
--
-- Killing the dispatchers above is what stops the server taking new
-- connections: nothing reads the sockets any more, so an Initial that
-- arrives now goes unanswered and is retried a PTO later -- by which time
-- the successor has the port and answers it instead.
--
-- What killing them cannot do is say anything to the connections that are
-- already here.  Left alone they find out when the sockets close under
-- them, which is too late to tell anyone, and each peer is left with a
-- connection that answers nothing until its idle timeout expires half a
-- minute later.  So each of them is ended here, through the same path that
-- ends a connection for any other reason, and the peer is sent a
-- CONNECTION_CLOSE while there is still a socket to send it on.  A peer
-- that hears it can open a new connection at once, and the successor is
-- there to answer.
--
-- Hearing the peers is another matter: once the successor has the port, on
-- Linux it is the successor that receives.  See Note [Binding the same port
-- twice].  Sending still works, which is what this relies on.
--
-- Each is ended from a thread of its own, because 'throwTo' waits for the
-- exception to be taken and a connection whose application is slow to
-- unwind would hold up the rest.

-- | Telling every connection to stop, and waiting until none is left.
--
-- Waiting matters because the caller owns the sockets.  Returning while a
-- connection still runs leaves it using a socket the caller is about to
-- close, and what that costs is not theoretical: the connection's last
-- CONNECTION_CLOSE went out on a closed descriptor and was lost, so the
-- peer heard nothing and sat until its idle timeout.  It is also a thread
-- reading a descriptor number that the kernel may hand to someone else.
--
-- Each connection is told once.  Telling it again a second later cannot
-- hurry a connection that is already closing down under 'mask', and what it
-- does reach is the CONNECTION_CLOSE being sent -- which it then interrupts
-- and loses, which is the thing this is here to prevent.  The second pass
-- is only to tell connections that were not yet in the table when the first
-- one looked.
--
-- There is no cap on the wait.  An application that never finishes with a
-- connection therefore keeps the server from returning, which is a
-- deliberate choice: the alternative is returning while it runs, which is
-- what this changed.  http3 caps the wait it does of its own, so an H3
-- connection comes back within that cap however its handler behaves.
shutdownConnections :: ServerConfig -> Dispatch -> IO ()
shutdownConnections conf dispatch = loop []
  where
    (err, reason) = scCloseReason conf
    shut conn = abortConnection conn err reason
    loop told = do
        conns <- liveConnections dispatch
        let unTold = [conn | conn <- conns, mainThreadId conn `notElem` told]
        mapM_ (void . forkIO . shut) unTold
        done <- T.timeout 1000000 $ waitNoConnection dispatch
        case done of
            Just () -> return ()
            Nothing -> loop $ map mainThreadId unTold ++ told

-- | Running a dispatcher on each socket.  The caller ends them all
--   together, by telling them, so there is nothing to undo here for the
--   ones already running.
runAll
    :: Dispatch
    -> ServerConfig
    -> TVar ServerState
    -> (Accept -> IO ())
    -> [NS.Socket]
    -> IO ()
runAll dispatch conf stvar forkConn = mapM_ $ runDispatcher dispatch conf stvar forkConn

-- Typically, ConnectionIsClosed breaks acceptStream.
-- And the exception should be ignored.
runServer
    :: ServerConfig
    -> (Connection -> IO ())
    -> Dispatch
    -> Accept
    -> IO ()
runServer conf server0 dispatch acc = do
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
    open = createServerConnection conf dispatch acc
    -- Stop this connection's own threads and see them out before the
    -- buffers they use are freed.  Nothing stopped them here at all: a path
    -- validation outlived the connection it was validating a path for, and
    -- went on reading and writing buffers that had been handed back.
    clse connRes = do
        let conn = connResConnection connRes
        setDead conn
        killReaders conn
        waitManaged conn
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
    -> IO ConnRes
createServerConnection conf@ServerConfig{..} dispatch Accept{..} = do
    retire0 <- newTVarIO False
    sref <- newIORef (accMySocket, retire0)
    pathInfo <- newPathInfo accPeerSockAddr
    piref <- newIORef $ PeerInfo pathInfo Nothing
    let send buf siz = void $ do
            (sock, _) <- readIORef sref
            PeerInfo pinfo _ <- readIORef piref
            NS.sendBufTo sock buf siz $ peerSockAddr pinfo
        recv = recvServer accRecvQ
    let myCID = fromJust $ initSrcCID accMyAuthCIDs
        ocid = fromJust $ origDstCID accMyAuthCIDs
    -- Nothing here is under 'runServer's bracket: that bracket's acquire is
    -- this function, so whatever it has taken when it throws is released by
    -- nobody.  It was taking two log files, three 2048-byte buffers and a
    -- registration in the dispatcher, and a connection setup does fail --
    -- 'dirQLogger' says how, and that is what it was doing in the field.
    --
    -- One releaser is in force at a time.  The logs stay this function's own
    -- until the end and are handed to the connection only once nothing is
    -- left that can throw, so 'freeResources' and the handlers here never
    -- both close the same thing.
    (qLog, qclean) <- dirQLogger scQLog accTime ocid "server"
    (debugLog, dclean) <- dirDebugLogger scDebugLog ocid `E.onException` qclean
    flip E.onException (dclean >> qclean) $ do
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
        flip E.onException (setDead conn >> freeResources conn) $ do
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
            setStopServer conn $ stopServerNow dispatch
            --
            setRegister conn accRegister accUnregister
            accRegister myCID conn
            addResource conn $ do
                myCIDs <- getMyCIDs conn
                mapM_ accUnregister myCIDs
            -- Handing the logs over.  Nothing below can throw, so from here
            -- 'freeResources' is the only releaser and the handlers above
            -- have nothing left to free.
            addResource conn qclean
            addResource conn dclean
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
