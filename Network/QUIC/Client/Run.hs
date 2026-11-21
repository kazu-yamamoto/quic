{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client.Run (
    run,
    runGivingUp,
    migrate,
) where

import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Network.Socket as NS

import Network.QUIC.Client.Reader
import Network.QUIC.Client.WatchDog
import Network.QUIC.Closer
import Network.QUIC.Common
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Crypto
import Network.QUIC.Exception (handleLogUnit)
import Network.QUIC.Handshake
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Parameters
import Network.QUIC.QLogger
import Network.QUIC.Receiver
import Network.QUIC.Recovery
import Network.QUIC.Sender
import Network.QUIC.Types

----------------------------------------------------------------

-- | Running a QUIC client.
--   A UDP socket is created according to 'ccServerName' and 'ccPortName'.
--
--   If the server closes the connection with NO_ERROR, an operation waiting
--   on the server throws 'ConnectionIsClosed'.  Otherwise the action runs to
--   its end, and its result is returned.
run :: ClientConfig -> (Connection -> IO a) -> IO a
run conf client = runWith conf client retry

-- | 'run', giving up once the 'STM' action succeeds, whether the
--   connection is still in its handshake or not: it is closed with
--   NO_ERROR, and what the action gave is returned as 'Left'.  An action
--   already done by then is not given up on.  The action is run once more
--   for what it gave: it should go on succeeding once it has, as a
--   deadline does.  Resolving 'ccServerName' is not given up on: it is
--   done before, and takes as long as the resolver does.
--
-- @since 0.4.0
runGivingUp :: ClientConfig -> (Connection -> IO a) -> STM g -> IO (Either g a)
runGivingUp conf client giveUp = do
    r <- E.try $ runWith conf client $ void giveUp
    case r of
        Right x -> return $ Right x
        -- Whatever the connection ended with, it was given up on.  Not
        -- the caller being killed, though: that goes on.
        Left (e :: E.SomeException)
            | isAsyncException e -> E.throwIO e
            | otherwise -> do
                mg <- atomically $ (Just <$> giveUp) `orElse` return Nothing
                maybe (E.throwIO e) (return . Left) mg

runWith :: ClientConfig -> (Connection -> IO a) -> STM () -> IO a
-- Don't use handleLogUnit here because of a return value.
runWith conf client giveUp = do
    let resInfo = ccResumption conf
        verInfo = case resumptionSession resInfo of
            []
                | resumptionToken resInfo == emptyToken ->
                    let ver = ccVersion conf
                        vers = ccVersions conf
                     in VersionInfo ver vers
            _ -> let ver = resumptionVersion resInfo in VersionInfo ver [ver]
    -- Exceptions except NextVersion are passed through.
    ex <- E.try $ runClient conf client giveUp False verInfo
    case ex of
        Right v -> return v
        -- Other exceptions go though.
        Left (NextVersion nextVerInfo)
            | nextVerInfo == brokenVersionInfo -> E.throwIO VersionNegotiationFailed
            | otherwise -> runClient conf client giveUp True nextVerInfo

runClient
    :: ClientConfig -> (Connection -> IO a) -> STM () -> Bool -> VersionInfo -> IO a
runClient conf client0 giveUp isICVN verInfo = do
    E.bracket open clse $ \(ConnRes conn myAuthCIDs reader) -> do
        forkManaged conn "QUIC reader" reader
        let conf' =
                conf
                    { ccParameters =
                        (ccParameters conf)
                            { versionInformation = Just verInfo
                            }
                    }
        setIncompatibleVN conn isICVN -- must be before handshaker
        setToken conn $ resumptionToken $ ccResumption conf
        handshaker <- handshakeClient conf' conn myAuthCIDs
        let client = do
                -- For 0-RTT, the following variables should be initialized
                -- in advance -- from the parameters the previous connection
                -- gave, which is what RFC 9000 Sec 7.4.1 holds a client
                -- sending 0-RTT to, and not from 'defaultParameters'.  Those
                -- are 64 bidi streams and 10 uni where a server may have
                -- allowed fewer, and since each of these setters only ever
                -- raises, a limit too high here stayed too high for the rest
                -- of the connection.  The connection's own send limit
                -- belongs with them and was missing altogether: it starts at
                -- zero and nothing raised it before the handshake, so 0-RTT
                -- stream data went out against no connection limit at all.
                --
                -- Only for 0-RTT: without it, these limits are the ones the
                -- handshake gives, and since the setters only raise, starting
                -- from those of a previous connection kept the client to
                -- them when the server had lowered its own since.
                when (remembers conf) $ do
                    params <- getPeerParameters conn
                    setTxMaxData conn $ initialMaxData params
                    setTxMaxStreams conn $ initialMaxStreamsBidi params
                    setTxUniMaxStreams conn $ initialMaxStreamsUni params
                if ccUse0RTT conf
                    then wait0RTTReady conn
                    else wait1RTTReady conn
                r <- client0 conn
                mainDone conn
                return r
            ldcc = connLDCC conn
        let rec = recordingEnd conn
            s1 = labelMe "handshaker" >> rec handshaker
            s2 = labelMe "sender" >> rec (sender conn)
            s3 = labelMe "receiver" >> rec (receiver conn)
            s4 = labelMe "resender" >> rec (resender ended ldcc)
            s5 = labelMe "ldccTimer" >> rec (ldccTimer ended ldcc)
            s6 = labelMe "QUIC client" >> client
            s7 = labelMe "abort watcher" >> rec (watchAbortRequest conn giveUp)
            ended = connectionEndedSTM conn
            protocol = withIdle conn $ runProtocolThreads [s1, s2, s3, s4, s5, s7]
            c5 =
                labelMe "concurrently5"
                    >> concurrentlyApp conn (protocol `E.catches` handlers) s6
            -- A peer closing with NO_ERROR leaves the application to finish:
            -- what waits on the peer gives up with 'ConnectionIsClosed'.
            handlers =
                [ E.Handler exitedNormally
                , E.Handler $ \e -> case e of
                    ConnectionIsClosed _ -> return ()
                    _ -> E.throwIO e
                ]
            runThreads = snd <$> c5
        -- A migration failing, with the network down, or the connection
        -- ended, is said in the log: it used to kill the thread, printed.
        when (ccWatchDog conf) $
            forkManaged conn "QUIC watchDog" $
                watchDog $
                    handleLogUnit (connDebugLog conn) (void $ migrate conn)
        ex <- E.try runThreads >>= abortRequested conn
        setConnectionEnd conn $ either id (const endedNormally) ex
        sendFinal conn
        setConnectionClosed conn
        closure conn ldcc ex
  where
    open = createClientConnection conf verInfo
    -- 'killReaders' sees the readers out, which has to happen before the
    -- buffers they use are freed.  This used to free first and stop after,
    -- which left every reader a window in which to use a buffer that had
    -- been handed back.
    clse connRes = do
        let conn = connResConnection connRes
        setDead conn
        killReaders conn
        -- Only the closer closes the socket, and there is none when the
        -- peer ended the connection.  No thread is on the socket now.
        owned <- readIORef $ connCloserOwnsSocket conn
        unless owned $ getSocket conn >>= NS.unsafeClose
        freeResources conn

-- | Whether this client sends 0-RTT, and so starts from the transport
--   parameters it remembers (RFC 9000 Sec 7.4.1).
remembers :: ClientConfig -> Bool
remembers ClientConfig{..} = ccUse0RTT && is0RTTPossible ccResumption

createClientConnection :: ClientConfig -> VersionInfo -> IO ConnRes
createClientConnection conf@ClientConfig{..} verInfo = do
    (sock, peersa) <- clientSocket ccServerName ccPortName
    -- As in 'createServerConnection': this is 'run's bracket acquire, so
    -- nothing releases what it has taken when it throws.  Here that is a
    -- socket as well -- 'clse' does not close it, the closer does, and a
    -- connection that never began has no closer.
    --
    -- Nothing below forks, and the reader is only built here, so this
    -- thread is the only one the socket has ever had.
    flip E.onException (NS.unsafeClose sock) $ do
        when ccSockConnected $ NS.connect sock peersa
        q <- newRecvQ =<< newRecvBudget maxBound
        retire0 <- newTVarIO False
        sref <- newIORef (sock, retire0)
        pathInfo <- newPathInfo peersa
        piref <- newIORef $ PeerInfo pathInfo Nothing
        let send buf siz
                | ccSockConnected = do
                    (s, _) <- readIORef sref
                    void $ NS.sendBuf s buf siz
                | otherwise = do
                    (s, _) <- readIORef sref
                    PeerInfo pinfo _ <- readIORef piref
                    void $ NS.sendBufTo s buf siz $ peerSockAddr pinfo
            recv = recvClient q
        myCID <- newCID
        -- Creating peer's CIDDB with the temporary CID.  This is
        -- overridden by resetPeerCID later since no sequence number is
        -- assigned to the temporary CID by spec.
        peerCID <- newCID
        now <- getTimeMicrosecond
        (qLog, qclean) <- dirQLogger ccQLog now peerCID "client"
        flip E.onException qclean $ do
            let debugLog msg
                    | ccDebugLog = stdoutLogger msg
                    | otherwise = return ()
            debugLog $ "Original CID: " <> bhow peerCID
            let myAuthCIDs = defaultAuthCIDs{initSrcCID = Just myCID}
                peerAuthCIDs = defaultAuthCIDs{initSrcCID = Just peerCID, origDstCID = Just peerCID}
            genSRT <- makeGenStatelessReset
            connRecvDatagramQ <- newDatagramQ
            conn <-
                clientConnection
                    conf
                    verInfo
                    myAuthCIDs
                    peerAuthCIDs
                    debugLog
                    qLog
                    ccHooks
                    sref
                    piref
                    q
                    connRecvDatagramQ
                    send
                    recv
                    genSRT
            flip E.onException (setDead conn >> freeResources conn) $ do
                setSockConnected conn ccSockConnected
                -- What RFC 9000 Sec 7.4.1 has a client remember, for 0-RTT
                -- alone.
                when (remembers conf) $ modifytPeerParameters conn ccResumption
                let ver = chosenVersion verInfo
                initializeCoder conn InitialLevel $ initialSecrets ver peerCID
                setupCryptoStreams conn -- fixme: cleanup
                -- RFC9000 \S14.2
                -- "In the absence of these mechanisms, QUIC endpoints SHOULD
                -- NOT send datagrams larger than the smallest allowed maximum
                -- datagram size."
                --
                -- Thus use 1200 bytes for minimum packet size.
                let pktSiz0 = fromMaybe (defaultPacketSize peersa) ccPacketSize
                    pktSiz = (defaultQUICPacketSize `max` pktSiz0) `min` maximumPacketSize peersa
                setMaxPacketSize conn pktSiz
                setInitialCongestionWindow (connLDCC conn) pktSiz
                setAddressValidated pathInfo
                retired <- getSocketRetire conn
                let reader = readerClient retired sock conn
                -- Handing the qlog over.  Nothing below can throw, so from here
                -- 'freeResources' is the only releaser.
                addResource conn qclean
                return $ ConnRes conn myAuthCIDs reader

-- | Creating a new socket and execute a path validation
--   with a new connection ID. Typically, this is used
--   for migration in the case where 'ccSockConnected' is 'True'.
--   But this can also be used even when the value is 'False'.
migrate :: Connection -> IO Bool
migrate conn = controlConnection conn ActiveMigration
