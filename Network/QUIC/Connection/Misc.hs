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
    forkManaged,
    killReaders,
    addResource,
    freeResources,
    readMinIdleTimeout,
    setMinIdleTimeout,
    sendFrames,
    closeConnection,
    abortConnection,
) where

import Control.Concurrent
import qualified Control.Exception as E
import qualified Data.Map.Strict as Map
import Network.Socket (SockAddr, Socket)
import System.Mem.Weak

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

addReader :: Connection -> ThreadId -> IO ()
addReader Connection{..} tid = do
    wtid <- mkWeakThreadId tid
    let n = fromThreadId tid
    atomicModifyIORef'' readers $ Map.insert n wtid

delReader :: Connection -> ThreadId -> IO ()
delReader Connection{..} tid = do
    let n = fromThreadId tid
    atomicModifyIORef'' readers $ Map.delete n

forkManaged :: Connection -> IO () -> IO ()
forkManaged conn action = void $ forkIO $ do
    E.bracket setup clean $ \_ -> action
  where
    setup = do
        tid <- myThreadId
        addReader conn tid
        return tid
    clean = delReader conn

killReaders :: Connection -> IO ()
killReaders Connection{..} = do
    wtids <- readIORef readers
    forM_ wtids $ \wtid -> do
        mtid <- deRefWeak wtid
        case mtid of
            Nothing -> return ()
            Just tid -> killThread tid

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
