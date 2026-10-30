{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Network.QUIC.Connection.Misc (
    setVersionInfo,
    getVersionInfo,
    setVersion,
    getVersion,
    getOriginalVersion,
    getSocket,
    setSocket,
    getSocketRetire,
    swapSocket,
    clearSocket,
    retireSocket,
    closeRetiredSockets,
    getPathInfo,
    addPathInfo,
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
    readMinIdleTimeout,
    setMinIdleTimeout,
    sendFrames,
    closeConnection,
    abortConnection,
) where

import Control.Concurrent.STM (TVar, atomically, writeTVar)
import qualified Control.Exception as E
import Network.Socket (SockAddr, Socket, unsafeClose)
import qualified System.ThreadManager as T

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Timeout
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
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

readMinIdleTimeout :: Connection -> IO Microseconds
readMinIdleTimeout Connection{..} = readIORef minIdleTimeout

setMinIdleTimeout :: Connection -> Microseconds -> IO ()
setMinIdleTimeout Connection{..} us
    | us == Microseconds 0 = return ()
    | otherwise = atomicModifyIORef'' minIdleTimeout modify
  where
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
abortConnection
    :: Connection -> ApplicationProtocolError -> ReasonPhrase -> IO ()
abortConnection conn err desc = E.throwTo (mainThreadId conn) $ Abort err desc
