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
    clearSocket,
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
    setSocketReader,
    getSocketReader,
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

import Control.Concurrent (MVar, ThreadId)
import qualified Control.Exception as E
import Network.Socket (SockAddr, Socket)
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
getSocket Connection{..} = readIORef connSocket

setSocket :: Connection -> Socket -> IO Socket
setSocket Connection{..} sock = atomicModifyIORef' connSocket (sock,)

-- | Taking over as the reader of this connection's socket, and giving
--   back the one displaced.  The handle is an 'MVar' rather than the
--   'ThreadId' itself so that a reader forked but not yet running is
--   waited for rather than missed.
setSocketReader :: Connection -> MVar ThreadId -> IO (Maybe (MVar ThreadId))
setSocketReader Connection{..} var = atomicModifyIORef' socketReader (Just var,)

getSocketReader :: Connection -> IO (Maybe (MVar ThreadId))
getSocketReader Connection{..} = readIORef socketReader

-- fixme
clearSocket :: Connection -> IO Socket
clearSocket Connection{..} = atomicModifyIORef' connSocket (undefined,)

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

-- | Killing the threads of 'forkManaged'.  One forked after this is
--   refused rather than run.
killReaders :: Connection -> IO ()
killReaders Connection{..} = T.stopAfter readers (return ()) $ \_ -> return ()

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
