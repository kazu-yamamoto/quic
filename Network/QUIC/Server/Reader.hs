{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Server.Reader (
    Dispatch,
    newDispatch,
    clearDispatch,
    runDispatcher,
    tokenMgr,
    genStatelessReset,

    -- * Accepting
    Accept (..),

    -- * Receiving and reading
    RecvQ,
    recvServer,
    ServerState (..),
) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Crypto.Token as CT
import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M
import qualified GHC.IO.Exception as E
import Network.ByteOrder
import Network.Control (LRUCacheRef, Rate, getRate, newRate)
import qualified Network.Control as LRUCache
import Network.Socket (SockAddr, Socket, waitReadSocketSTM)
import qualified Network.Socket.ByteString as NSB
import qualified System.IO.Error as E
import System.Log.FastLogger
import System.Random (getStdRandom, randomRIO, uniformByteString)

import Network.QUIC.Common
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Types
import Network.QUIC.Windows

----------------------------------------------------------------

data Dispatch = Dispatch
    { tokenMgr :: CT.TokenManager
    , dstTable :: IORef ConnectionDict
    , srcTable :: RecvQDict
    , genStatelessReset :: CID -> StatelessResetToken
    , statelessResetRate :: Rate
    }

statelessResetLimit :: Int
statelessResetLimit = 20

newDispatch :: ServerConfig -> IO Dispatch
newDispatch ServerConfig{..} =
    Dispatch
        <$> CT.spawnTokenManager conf
        <*> newIORef emptyConnectionDict
        <*> newRecvQDict
        <*> makeGenStatelessReset
        <*> newRate
  where
    conf =
        CT.defaultConfig
            { CT.tokenLifetime = scTicketLifetime
            , CT.threadName = "QUIC token manager"
            }

clearDispatch :: Dispatch -> IO ()
clearDispatch d = CT.killTokenManager $ tokenMgr d

----------------------------------------------------------------

newtype ConnectionDict = ConnectionDict (Map CID Connection)

emptyConnectionDict :: ConnectionDict
emptyConnectionDict = ConnectionDict M.empty

lookupConnectionDict :: IORef ConnectionDict -> CID -> IO (Maybe Connection)
lookupConnectionDict ref cid = do
    ConnectionDict tbl <- readIORef ref
    return $ M.lookup cid tbl

registerConnectionDict :: IORef ConnectionDict -> CID -> Connection -> IO ()
registerConnectionDict ref cid conn = atomicModifyIORef'' ref $
    \(ConnectionDict tbl) -> ConnectionDict $ M.insert cid conn tbl

unregisterConnectionDict :: IORef ConnectionDict -> CID -> IO ()
unregisterConnectionDict ref cid = atomicModifyIORef'' ref $
    \(ConnectionDict tbl) -> ConnectionDict $ M.delete cid tbl

----------------------------------------------------------------

-- Source CID -> RecvQ
-- Initials and RTT0 are queued before Conneciton is created.
newtype RecvQDict = RecvQDict (LRUCacheRef CID RecvQ)

recvQDictSize :: Int
recvQDictSize = 100

newRecvQDict :: IO RecvQDict
newRecvQDict = RecvQDict <$> LRUCache.newLRUCacheRef recvQDictSize

-- Looking up and insert a new RecvQ if not exist.
lookupInsertRecvQDict :: RecvQDict -> CID -> IO (RecvQ, Bool)
lookupInsertRecvQDict (RecvQDict ref) dcid = LRUCache.cached ref dcid newRecvQ

lookupRecvQDict :: RecvQDict -> CID -> IO (Maybe RecvQ)
lookupRecvQDict (RecvQDict ref) dcid = LRUCache.cached' ref dcid

----------------------------------------------------------------

data Accept = Accept
    { accVersionInfo :: VersionInfo
    , accMyAuthCIDs :: AuthCIDs
    , accPeerAuthCIDs :: AuthCIDs
    , accMySocket :: Socket
    , accPeerSockAddr :: SockAddr
    , accRecvQ :: RecvQ
    , accPacketSize :: Int
    , accRegister :: CID -> Connection -> IO ()
    , accUnregister :: CID -> IO ()
    , accAddressValidated :: Bool
    , accTime :: TimeMicrosecond
    }

----------------------------------------------------------------

runDispatcher
    :: Dispatch
    -> ServerConfig
    -> TVar ServerState
    -> (Accept -> IO ())
    -> Socket
    -> IO ThreadId
runDispatcher d conf stvar forkConn mysock = forkIO $ dispatcher d conf stvar forkConn mysock

data ServerState = Running | Stopped deriving (Eq, Show)

checkLoop :: TVar ServerState -> Socket -> IO Bool
checkLoop stvar mysock = do
    st0 <- readTVarIO stvar
    if st0 == Stopped
        then return False
        else do
            wait <- waitReadSocketSTM mysock
            atomically $ do
                st <- readTVar stvar
                if st == Stopped
                    then return False
                    else do
                        wait -- blocking is retry
                        return True

dispatcher
    :: Dispatch
    -> ServerConfig
    -> TVar ServerState
    -> (Accept -> IO ())
    -> Socket
    -> IO ()
dispatcher d conf stvar forkConnection mysock = do
    labelMe "QUIC dispatcher"
    handleLogUnit logAction loop
  where
    loop = do
        cont <- checkLoop stvar mysock
        when cont $ do
            (bs, peersa) <- safeRecv $ NSB.recvFrom mysock 2048
            now <- getTimeMicrosecond
            let send' b = void $ NSB.sendTo mysock b peersa
                -- cf: greaseQuicBit $ getMyParameters conn
                quicBit = greaseQuicBit $ scParameters conf
            cpckts <- decodeCryptPackets bs (not quicBit)
            let bytes = BS.length bs
                switch = dispatch d conf forkConnection logAction mysock peersa send' bytes now
            mapM_ switch cpckts
            loop

    logAction _msg = return ()

    safeRecv rcv = do
        ex <- E.try $ windowsThreadBlockHack rcv
        case ex of
            Right x -> return x
            Left se | isAsyncException se -> E.throwIO (se :: E.SomeException)
            Left se -> case E.fromException se of
                Just e | E.ioeGetErrorType e == E.InvalidArgument -> E.throwIO se
                _ -> do
                    logAction $ "recv again: " <> bhow se
                    rcv

----------------------------------------------------------------

-- If client initial is fragmented into multiple packets,
-- there is no way to put the all packets into a single queue.
-- Rather, each fragment packet is put into its own queue.
-- For the first fragment, handshake would successif others are
-- retransmitted.
-- For the other fragments, handshake will fail since its socket
-- cannot be connected.
dispatch
    :: Dispatch
    -> ServerConfig
    -> (Accept -> IO ())
    -> DebugLogger
    -> Socket
    -> SockAddr
    -> (ByteString -> IO ())
    -> Int
    -> TimeMicrosecond
    -> (CryptPacket, EncryptionLevel, Int)
    -> IO ()
dispatch
    Dispatch{..}
    ServerConfig{..}
    forkConnection
    logAction
    mysock
    peersa
    send'
    bytes
    tim
    (cpkt@(CryptPacket (Initial peerVer dCID sCID token) _), lvl, siz)
        | bytes < defaultQUICPacketSize = do
            logAction $ "too small " <> bhow bytes <> ", " <> bhow peersa
        | peerVer `notElem` myVersions = do
            let offerVersions
                    | peerVer == GreasingVersion = GreasingVersion2 : myVersions
                    | otherwise = GreasingVersion : myVersions
            bss <-
                encodeVersionNegotiationPacket $
                    VersionNegotiationPacket sCID dCID offerVersions
            send' bss
        | token == "" = do
            mconn <- lookupConnectionDict dstTable dCID
            case mconn of
                Nothing
                    | scRequireRetry -> sendRetry
                    | otherwise -> pushToAcceptFirst False
                Just conn -> writeRecvQ (connRecvQ conn) $ mkReceivedPacket cpkt tim siz lvl
        | otherwise = do
            mconn <- lookupConnectionDict dstTable dCID
            case mconn of
                Nothing -> do
                    mct <- decryptToken tokenMgr token
                    case mct of
                        Just ct
                            | isRetryToken ct -> do
                                ok <- isRetryTokenValid ct
                                if ok then pushToAcceptRetried ct else sendRetry
                        _ -> pushToAcceptFirst True
                Just conn -> writeRecvQ (connRecvQ conn) $ mkReceivedPacket cpkt tim siz lvl
      where
        myVersions = scVersions
        pushToAcceptQ myAuthCIDs peerAuthCIDs addrValid = do
            let key = nonZeroLengthCID sCID peersa
            (q, exist) <- lookupInsertRecvQDict srcTable key
            writeRecvQ q $ mkReceivedPacket cpkt tim siz lvl
            unless exist $ do
                let reg = registerConnectionDict dstTable
                    unreg cid =
                        fire' (Microseconds 10000000) $ unregisterConnectionDict dstTable cid
                    acc =
                        Accept
                            { accVersionInfo = VersionInfo peerVer myVersions
                            , accMyAuthCIDs = myAuthCIDs
                            , accPeerAuthCIDs = peerAuthCIDs
                            , accMySocket = mysock
                            , accPeerSockAddr = peersa
                            , accRecvQ = q
                            , accPacketSize = bytes
                            , accRegister = reg
                            , accUnregister = unreg
                            , accAddressValidated = addrValid
                            , accTime = tim
                            }
                forkConnection acc
        -- Initial: DCID=S1, SCID=C1 ->
        --                                     <- Initial: DCID=C1, SCID=S2
        --                               ...
        -- 1-RTT: DCID=S2 ->
        --                                                <- 1-RTT: DCID=C1
        --
        -- initial_source_connection_id       = S2   (newdCID)
        -- original_destination_connection_id = S1   (dCID)
        -- retry_source_connection_id         = Nothing
        pushToAcceptFirst addrValid = do
            newdCID <- newCID
            let myAuthCIDs =
                    defaultAuthCIDs
                        { initSrcCID = Just newdCID
                        , origDstCID = Just dCID
                        }
                peerAuthCIDs =
                    defaultAuthCIDs
                        { initSrcCID = Just sCID
                        }
            pushToAcceptQ myAuthCIDs peerAuthCIDs addrValid
        -- Initial: DCID=S1, SCID=C1 ->
        --                                       <- Retry: DCID=C1, SCID=S2
        -- Initial: DCID=S2, SCID=C1 ->
        --                                     <- Initial: DCID=C1, SCID=S3
        --                               ...
        -- 1-RTT: DCID=S3 ->
        --                                                <- 1-RTT: DCID=C1
        --
        -- initial_source_connection_id       = S3   (dCID)  S2 in our server
        -- original_destination_connection_id = S1   (o)
        -- retry_source_connection_id         = S2   (dCID)
        pushToAcceptRetried (CryptoToken _ _ _ (Just (_, _, o))) = do
            let myAuthCIDs =
                    defaultAuthCIDs
                        { initSrcCID = Just dCID
                        , origDstCID = Just o
                        , retrySrcCID = Just dCID
                        }
                peerAuthCIDs =
                    defaultAuthCIDs
                        { initSrcCID = Just sCID
                        }
            pushToAcceptQ myAuthCIDs peerAuthCIDs True
        pushToAcceptRetried _ = return ()
        isRetryTokenValid (CryptoToken _tver life etim (Just (l, r, _))) = do
            diff <- getElapsedTimeMicrosecond etim
            return $
                diff <= Microseconds (fromIntegral life * 1000000)
                    && dCID == l
                    && sCID == r
                    -- Initial for ACK contains the retry token but
                    -- the version would be already version 2, sigh.
                    && _tver == peerVer
        isRetryTokenValid _ = return False
        sendRetry = do
            newdCID <- newCID
            retryToken <- generateRetryToken peerVer scTicketLifetime newdCID sCID dCID
            mnewtoken <-
                timeout (Microseconds 100000) "sendRetry" $ encryptToken tokenMgr retryToken
            case mnewtoken of
                Nothing -> logAction "retry token stacked"
                Just newtoken -> do
                    bss <- encodeRetryPacket $ RetryPacket peerVer sCID newdCID newtoken (Left dCID)
                    send' bss
----------------------------------------------------------------
dispatch
    Dispatch{..}
    _
    _
    _
    _mysock
    peersa
    _
    _
    tim
    (cpkt@(CryptPacket (RTT0 _ _dCID sCID) _), lvl, siz) = do
        let key = nonZeroLengthCID sCID peersa
        mq <- lookupRecvQDict srcTable key
        case mq of
            Just q -> writeRecvQ q $ mkReceivedPacket cpkt tim siz lvl
            Nothing -> return ()
----------------------------------------------------------------
dispatch
    Dispatch{..}
    _
    _
    logAction
    mysock
    peersa
    send'
    bytes
    tim
    (cpkt@(CryptPacket (Short dCID) _), lvl, siz) = do
        mconn <- lookupConnectionDict dstTable dCID
        case mconn of
            Nothing -> do
                -- Three times rule for stateless reset
                -- Our packet size is 1280
                when (bytes > 427) $ do
                    srRate <- getRate statelessResetRate
                    -- fixme: hard coding
                    when (srRate < statelessResetLimit) $ do
                        flag <- randomRIO (0, 127)
                        body <- getStdRandom $ uniformByteString 1263
                        let srt = genStatelessReset dCID
                            statelessReset = BS.concat [BS.singleton flag, body, fromStatelessResetToken srt]
                        send' statelessReset
                        logAction $ "Stateless reset is sent to " <> bhow peersa
            Just conn -> do
                alive <- getAlive conn
                when alive $ do
                    void $ setSocket conn mysock -- fixme
                    curCID <- getMyCID conn
                    -- setMyCID is not called here since setMyCID is
                    -- done in Receiver.
                    let cidChanged = curCID /= dCID
                    mPathInfo <- findPathInfo conn peersa
                    case mPathInfo of
                        Nothing -> do
                            forkManaged conn $
                                onClientMigration conn dCID peersa cidChanged
                        _ -> return ()
                    writeRecvQ (connRecvQ conn) $ mkReceivedPacket cpkt tim siz lvl
----------------------------------------------------------------
dispatch
    Dispatch{..}
    _
    _
    logAction
    mysock
    peersa
    _
    _
    tim
    (cpkt@(CryptPacket hdr _crypt), lvl, siz) = do
        let dCID = headerMyCID hdr
        mconn <- lookupConnectionDict dstTable dCID
        case mconn of
            Nothing -> logAction $ "CID no match: " <> bhow dCID <> ", " <> bhow peersa
            Just conn -> do
                -- fixme: is this block necessary?
                void $ setSocket conn mysock
                mPathInfo <- findPathInfo conn peersa
                when (isNothing mPathInfo) $ do
                    pathInfo <- newPathInfo peersa
                    addPathInfo conn pathInfo
                writeRecvQ (connRecvQ conn) $ mkReceivedPacket cpkt tim siz lvl

recvServer :: RecvQ -> IO ReceivedPacket
recvServer = readRecvQ

onClientMigration :: Connection -> CID -> SockAddr -> Bool -> IO ()
onClientMigration conn newdCID peersa cidChanged = handleLogUnit logAction $ do
    migrating <- isPathValidating conn -- fixme: test and set
    unless migrating $ do
        setMigrationStarted conn
        -- fixme: should not block
        mcidinfo <-
            if cidChanged
                then timeout (Microseconds 100000) "onClientMigration" $ waitPeerCID conn
                else return Nothing -- PathChallenge only, no RetireConnectionID
        let msg = "Migration: " <> bhow peersa <> " (" <> bhow newdCID <> ")"
        qlogDebug conn $ Debug $ toLogStr msg
        connDebugLog conn $ "debug: onClientMigration: " <> msg
        pathInfo <- newPathInfo peersa
        -- assumed that this PathInfo is not stored in PeerInfo
        addPathInfo conn pathInfo
        validatePath conn pathInfo mcidinfo
  where
    logAction msg = connDebugLog conn ("debug: onClientMigration: " <> msg)
