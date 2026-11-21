{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Network.QUIC.Connection.Misc (
    setVersionInfo,
    getVersionInfo,
    setVersion,
    getVersion,
    getOriginalVersion,
    getSocket,
    getPathSocket,
    setSocket,
    getSocketRetire,
    swapSocket,
    clearSocket,
    retireSocket,
    closeRetiredSockets,
    getPathInfo,
    addPathInfo,
    restorePathInfo,
    findPathInfo,
    getPeerAuthCIDs,
    setPeerAuthCIDs,
    getClientDstCID,
    getMyParameters,
    getPeerParameters,
    setPeerParameters,
    modifytPeerParameters,
    delayedAck,
    resetDealyedAck,
    setMaxPacketSize,
    forkManaged,
    waitManaged,
    killReaders,
    addResource,
    freeResources,
    getIdleTimeout,
    setMinIdleTimeout,
    withIdle,
    keepAlive,
    workInProgress,
    sendFrames,
    closeConnection,
    abortConnection,
    requestEnd,
    watchAbortRequest,
    abortRequested,
    concurrentlyApp,
    runProtocolThreads,
    appGracePeriod,
) where

import Control.Concurrent.Async (pollSTM, wait, waitCatchSTM, withAsync)
import Control.Concurrent.STM (
    TVar,
    atomically,
    modifyTVar',
    orElse,
    readTVar,
    readTVarIO,
    registerDelay,
    retry,
    writeTVar,
 )
import qualified Control.Exception as E
import qualified Control.Monad.STM as STM
import Network.Socket (SockAddr, Socket, unsafeClose)
import qualified System.ThreadManager as T
import qualified System.Watchdog as W

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Timeout
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Recovery (getPTO)
import Network.QUIC.Stream (streamId, tableStreams)
import Network.QUIC.Types

----------------------------------------------------------------

setVersionInfo :: Connection -> VersionInfo -> IO ()
setVersionInfo Connection{..} ver = writeIORef quicVersionInfo ver

getVersionInfo :: Connection -> IO VersionInfo
getVersionInfo Connection{..} = readIORef quicVersionInfo

setVersion :: Connection -> Version -> IO ()
setVersion Connection{..} ver = atomicModifyIORef'' quicVersionInfo $ \vi ->
    vi{chosenVersion = ver}

getVersion :: Connection -> IO Version
getVersion conn = chosenVersion <$> getVersionInfo conn

getOriginalVersion :: Connection -> Version
getOriginalVersion = chosenVersion . origVersionInfo

----------------------------------------------------------------

getSocket :: Connection -> IO Socket
getSocket Connection{..} = fst <$> readIORef connSocket

-- | The socket the path in use sends on: a server's path has its own.
getPathSocket :: Connection -> IO Socket
getPathSocket conn = do
    PeerInfo pinfo _ <- readIORef $ peerInfo conn
    maybe (getSocket conn) return $ pathSocket pinfo

-- | Swapping the socket alone, leaving the reader of the old one to be
--   retired through the variable they share.
setSocket :: Connection -> Socket -> IO Socket
setSocket Connection{..} sock =
    atomicModifyIORef' connSocket $ \(old, retire) -> ((sock, retire), old)

-- | The variable which retires the reader of the current socket.
getSocketRetire :: Connection -> IO (TVar Bool)
getSocketRetire Connection{..} = snd <$> readIORef connSocket

-- | Swapping the socket and the variable which retires its reader at
--   once, returning the pair they replace.  The two go together, so
--   nothing can see one of them swapped and not the other.
swapSocket :: Connection -> Socket -> TVar Bool -> IO (Socket, TVar Bool)
swapSocket Connection{..} sock retire =
    atomicModifyIORef' connSocket ((sock, retire),)

-- | Leaving a socket this connection has finished with for the sender to
--   close.  Said by the reader on its way out, so that the only thread
--   which could still be inside a call on it is the sender.
--
-- The close is registered as a resource as well, so that leaving one here
-- is all it takes: a connection whose sender never wakes again closes it
-- in 'freeResources' instead.  Closing an already closed socket does
-- nothing, so it does not matter which gets there first.
retireSocket :: Connection -> Socket -> IO ()
retireSocket conn@Connection{..} sock = do
    atomicModifyIORef' connRetiredSocks $ \socks -> (sock : socks, ())
    addResource conn $ unsafeClose sock

-- | Closing what 'retireSocket' has left.  The caller must not be inside a
--   call on any of them, which is why this is the sender between two sends.
--   Nobody is waiting on them, so @close(2)@ is enough.
closeRetiredSockets :: Connection -> IO ()
closeRetiredSockets Connection{..} = do
    socks <- atomicModifyIORef' connRetiredSocks ([],)
    mapM_ unsafeClose socks

-- fixme
clearSocket :: Connection -> IO Socket
clearSocket Connection{..} =
    atomicModifyIORef' connSocket $ \(old, retire) -> ((undefined, retire), old)

----------------------------------------------------------------

getPathInfo :: Connection -> IO PathInfo
getPathInfo Connection{..} = currPathInfo <$> readIORef peerInfo

addPathInfo :: Connection -> PathInfo -> IO ()
addPathInfo Connection{..} newpi = atomicModifyIORef'' peerInfo add
  where
    add (PeerInfo oldpi _) = PeerInfo newpi $ Just oldpi

-- | Going back to a path, forgetting the one in use.
restorePathInfo :: Connection -> PathInfo -> IO ()
restorePathInfo Connection{..} oldpi = do
    PeerInfo failed _ <- readIORef peerInfo
    writeIORef peerInfo $ PeerInfo oldpi Nothing
    atomically $ writeTVar (pathAbandoned failed) True

findPathInfo :: Connection -> SockAddr -> IO (Maybe PathInfo)
findPathInfo Connection{..} sa = do
    PeerInfo currpi mprevpi <- readIORef peerInfo
    return $
        if peerSockAddr currpi == sa
            then Just currpi
            else
                if (peerSockAddr <$> mprevpi) == Just sa
                    then mprevpi
                    else Nothing

----------------------------------------------------------------

getMyAuthCIDs :: Connection -> IO AuthCIDs
getMyAuthCIDs Connection{..} = readIORef connMyAuthCIDs

getPeerAuthCIDs :: Connection -> IO AuthCIDs
getPeerAuthCIDs Connection{..} = readIORef connPeerAuthCIDs

setPeerAuthCIDs :: Connection -> (AuthCIDs -> AuthCIDs) -> IO ()
setPeerAuthCIDs Connection{..} f = atomicModifyIORef'' connPeerAuthCIDs f

getClientDstCID :: Connection -> IO CID
getClientDstCID conn = do
    cids <-
        if isClient conn
            then getPeerAuthCIDs conn
            else getMyAuthCIDs conn
    return $ case retrySrcCID cids of
        Nothing -> fromJust $ origDstCID cids
        Just dcid -> dcid

----------------------------------------------------------------

getMyParameters :: Connection -> Parameters
getMyParameters Connection{..} = myParameters

----------------------------------------------------------------

getPeerParameters :: Connection -> IO Parameters
getPeerParameters Connection{..} = readIORef peerParameters

setPeerParameters :: Connection -> Parameters -> IO ()
setPeerParameters Connection{..} params = writeIORef peerParameters params

modifytPeerParameters :: Connection -> ResumptionInfo -> IO ()
modifytPeerParameters Connection{..} ri =
    atomicModifyIORef'' peerParameters $ resumptionToParameters ri

resumptionToParameters :: ResumptionInfo -> Parameters -> Parameters
resumptionToParameters ResumptionInfo{..} params =
    params
        { activeConnectionIdLimit = resumptionActiveConnectionIdLimit
        , initialMaxData = resumptionInitialMaxData
        , initialMaxStreamDataBidiLocal = resumptionInitialMaxStreamDataBidiLocal
        , initialMaxStreamDataBidiRemote = resumptionInitialMaxStreamDataBidiRemote
        , initialMaxStreamDataUni = resumptionInitialMaxStreamDataUni
        , initialMaxStreamsBidi = resumptionInitialMaxStreamsBidi
        , initialMaxStreamsUni = resumptionInitialMaxStreamsUni
        , maxDatagramFrameSize = resumptionMaxDatagramFrameSize
        }

----------------------------------------------------------------

delayedAck :: Connection -> IO ()
delayedAck conn@Connection{..} = do
    (oldcnt, send_) <- atomicModifyIORef' delayedAckCount check
    when (oldcnt == 0) $ do
        new <- cfire conn (Microseconds 20000) sendAck
        join $ atomicModifyIORef' delayedAckCancel (new,)
    when send_ $ do
        let new = return ()
        join $ atomicModifyIORef' delayedAckCancel (new,)
        sendAck
  where
    sendAck = putOutput conn $ OutControl RTT1Level []
    check 1 = (0, (1, True))
    check n = (n + 1, (n, False))

resetDealyedAck :: Connection -> IO ()
resetDealyedAck Connection{..} = do
    writeIORef delayedAckCount 0
    let new = return ()
    join $ atomicModifyIORef' delayedAckCancel (new,)

----------------------------------------------------------------

setMaxPacketSize :: Connection -> Int -> IO ()
setMaxPacketSize Connection{..} n = writeIORef (maxPacketSize connState) n

----------------------------------------------------------------

addResource :: Connection -> IO () -> IO ()
addResource Connection{..} f = atomicModifyIORef'' connResources $ \fs -> f' >> fs
  where
    f' = f `E.catch` ignore

freeResources :: Connection -> IO ()
freeResources Connection{..} =
    join $ atomicModifyIORef' connResources (return (),)

----------------------------------------------------------------

forkManaged :: Connection -> String -> IO () -> IO ()
forkManaged Connection{..} = T.forkManaged readers

-- | Waiting until this connection's 'forkManaged' threads are all done.
--
-- What they are done with is the connection's buffers, so this has to come
-- between stopping them and 'freeResources'.
--
-- No cap on the wait: these are all this library's own threads and they
-- end on the exception 'killReaders' throws.  What http2 and http3 cap is
-- a wait that includes the application's handler.
waitManaged :: Connection -> IO ()
waitManaged Connection{..} = T.waitUntilAllGone readers

-- | Killing the threads of 'forkManaged' and seeing them out.  One forked
--   after this is refused rather than run.
--
-- 'T.stopAfter' throws and returns: 'throwTo' waits for the exception to be
-- taken, not for the thread to end, so without the wait a caller which goes
-- on to use what those threads were using -- the connection's socket, in
-- 'Network.QUIC.Closer' -- is racing them.  'waitManaged' says why there is
-- no cap on it.
killReaders :: Connection -> IO ()
killReaders conn@Connection{..} = do
    -- Telling the reader of the current socket to go.  'stopAfter' below
    -- throws into the threads it manages, and an asynchronous exception
    -- does not reach one blocked in a socket call on Windows; the reader
    -- waits on this variable beside its receive instead.
    retired <- getSocketRetire conn
    atomically $ writeTVar retired True
    T.stopAfter readers (return ()) $ \_ -> return ()
    waitManaged conn

----------------------------------------------------------------

-- | The idle timeout in effect, if any (RFC 9000 Sec 10.1): the smaller of
--   the two advertised, 0 being none, and at least three times the PTO.
getIdleTimeout :: Connection -> IO (Maybe Microseconds)
getIdleTimeout Connection{..} = do
    ito <- readIORef minIdleTimeout
    if ito == Microseconds 0
        then return Nothing
        else do
            pto <- getPTO connLDCC
            return $ Just $ max ito (3 * pto)

-- | Running the protocol threads under the idle timer.  The receiver
--   ends the connection by itself when it times out; should it not, the
--   others are asked to, rather than thrown at.
withIdle :: Connection -> IO a -> IO a
withIdle conn body = do
    setupIdle conn
    W.withWatchdog (connIdle conn) lastResort body
  where
    lastResort = requestEnd conn $ ConnectionIsTimeout "idle timeout"

-- | Telling the idle timer how long the connection may stay idle, whether
--   to keep it alive, and how.
setupIdle :: Connection -> IO ()
setupIdle conn =
    W.update (const $ Idle (getIdleTimeout conn) busy ping) $ connIdle conn
  where
    busy = (> 0) <$> readTVarIO (connBusy conn)
    -- The watchdog's probe: it must return at once, and enqueueing does.
    ping = do
        established <- isConnectionEstablished conn
        when established $ sendFrames conn RTT1Level [Ping]

-- | Keeping the connection from idling out while the action runs: when
--   the peer has been quiet for half the idle timeout, a PING goes out,
--   whose acknowledgment restarts the timer.  A peer which is gone still
--   times out (RFC 9000 10.1.2).
--
-- @since 0.4.0
keepAlive :: Connection -> IO a -> IO a
keepAlive conn = E.bracket_ (change 1) (change (-1))
  where
    -- Changed, so that the watchdog decides again.
    change n = atomically $ do
        modifyTVar' (connBusy conn) (+ n)
        touchIdle conn

-- | Whether something waits on the peer: a 'keepAlive' running, or a
--   bidirectional stream open.  An idle timeout then is the peer failing
--   it; otherwise the connection was merely unused.
workInProgress :: Connection -> IO Bool
workInProgress conn = do
    busy <- readTVarIO $ connBusy conn
    strms <- tableStreams <$> readTVarIO (streamTable conn)
    return $ busy > 0 || any (isBidirectional . streamId) strms

setMinIdleTimeout :: Connection -> Microseconds -> IO ()
setMinIdleTimeout Connection{..} us
    | us == Microseconds 0 = return ()
    | otherwise = atomicModifyIORef'' minIdleTimeout modify
  where
    -- Ours being none, the peer's alone is in effect.
    modify (Microseconds 0) = us
    modify us0 = min us us0

----------------------------------------------------------------

sendFrames :: Connection -> EncryptionLevel -> [Frame] -> IO ()
sendFrames conn lvl frames = putOutput conn $ OutControl lvl frames

-- | Closing a connection with/without a transport error.
--   Internal threads should use this.
closeConnection :: Connection -> TransportError -> ReasonPhrase -> IO ()
closeConnection _conn err desc = E.throwIO quicexc
  where
    quicexc = TransportErrorIsSent err desc

-- | Closing a connection with an application protocol error.
--
-- This asks and returns; the connection's protocol threads act on it
-- ('watchAbortRequest').  It used to throw to the connection's main thread,
-- and a connection that had just ended took the exception where nothing
-- caught it: in its teardown, or on the way out of the thread running it,
-- where the runtime reported it as uncaught.  A server stopping caught one
-- of its connections there now and then.  A connection already over now
-- just never looks.  The first request is the one acted on.
abortConnection
    :: Connection -> ApplicationProtocolError -> ReasonPhrase -> IO ()
abortConnection conn err desc = requestEnd conn $ Abort err desc

-- | Asking the connection's protocol threads to end it with this
--   exception, as 'abortConnection' does.  For threads outside them, such
--   as a reader, which used to throw to the connection's main thread.
requestEnd :: E.Exception e => Connection -> e -> IO ()
requestEnd Connection{..} e =
    atomically $ modifyTVar' connAbortRequest $ \r -> r <|> Just (E.toException e)

-- | A connection's ending, as 'requestEnd' asked for it if it did.
--   An application that asks and returns at once can see the protocol
--   threads end before they have acted on it; it is what it asked for all
--   the same.
abortRequested
    :: Connection -> Either E.SomeException a -> IO (Either E.SomeException a)
abortRequested Connection{..} ex@(Right _) = do
    req <- readTVarIO connAbortRequest
    return $ maybe ex Left req
abortRequested _ ex = return ex

-- | Waiting for 'requestEnd' and raising what it was asked with:
--   one of a connection's protocol threads, so that it ends the connection
--   as any of them failing does.  Returning once it has ended otherwise.
--   The 'STM' action given up on ends it with NO_ERROR, unless the
--   application is done by then: what it returned is not given up on.
watchAbortRequest :: Connection -> STM.STM () -> IO ()
watchAbortRequest conn@Connection{..} giveUp = do
    me <-
        atomically $
            (Just <$> (readTVar connAbortRequest >>= maybe retry return))
                `orElse` (Just givenUp <$ (readTVar connDone >>= STM.check . not >> giveUp))
                `orElse` (Nothing <$ connectionEndedSTM conn)
    mapM_ E.throwIO me
  where
    givenUp = E.toException $ TransportErrorIsSent NoError "given up"

----------------------------------------------------------------

-- | 'Control.Concurrent.Async.concurrently' for the protocol threads and
--   the application.  When the protocol threads fail, the application is
--   not cancelled at once: what it waits on in the connection throws why
--   the connection ended, and it has 'appGracePeriod' to finish by itself.
--   Only then is it cancelled.  The protocol threads' exception is thrown
--   either way, as it was.
concurrentlyApp :: IO a -> IO b -> IO (a, b)
concurrentlyApp protocol app =
    withAsync protocol $ \ap' -> withAsync app $ \aa -> do
        r <-
            atomically $ (Left <$> waitCatchSTM ap') `orElse` (Right <$> waitCatchSTM aa)
        case r of
            Left (Right x) -> (,) x <$> wait aa
            Left (Left e) -> do
                expired <- registerDelay appGracePeriod
                atomically $
                    void (waitCatchSTM aa) `orElse` (readTVar expired >>= STM.check)
                E.throwIO e
            Right (Right y) -> (,y) <$> wait ap'
            Right (Left e) -> E.throwIO e

-- | Running the protocol threads until each has returned.  When one
--   fails, the connection has ended and the others see it and return by
--   themselves; those still running after 'appGracePeriod' are cancelled
--   as a last resort.  The first failure is rethrown.
runProtocolThreads :: [IO ()] -> IO ()
runProtocolThreads = go []
  where
    go as (act : acts) = withAsync act $ \a -> go (a : as) acts
    go as [] = do
        mfailed <- atomically $ do
            rs <- mapM pollSTM as
            case [e | Just (Left e) <- rs] of
                e : _ -> return $ Just e
                []
                    | all isJust rs -> return Nothing
                    | otherwise -> retry
        forM_ mfailed $ \e -> do
            expired <- registerDelay appGracePeriod
            atomically $
                mapM_ waitCatchSTM as `orElse` (readTVar expired >>= STM.check)
            E.throwIO e

-- | How long the application, and then each protocol thread, has to
--   finish by itself once the protocol threads have failed (microseconds).
appGracePeriod :: Int
appGracePeriod = 1000000
