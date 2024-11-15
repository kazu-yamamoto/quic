{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Server.Reader (
    Dispatch,
    newDispatch,
    clearDispatch,
    runDispatcher,
    tokenMgr,

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
import Network.Control (LRUCache)
import qualified Network.Control as LRUCache
import Network.Socket (Socket, waitReadSocketSTM)
import qualified Network.Socket.ByteString as NSB
import qualified System.IO.Error as E

import Network.QUIC.Common
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Types
import Network.QUIC.Windows

----------------------------------------------------------------

data Dispatch = Dispatch
    { tokenMgr :: CT.TokenManager
    , dstTable :: IORef ConnectionDict
    , srcTable :: IORef RecvQDict
    }

newDispatch :: ServerConfig -> IO Dispatch
newDispatch ServerConfig{..} =
    Dispatch
        <$> CT.spawnTokenManager conf
        <*> newIORef emptyConnectionDict
        <*> newIORef emptyRecvQDict
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

-- Original destination CID -> RecvQ
newtype RecvQDict = RecvQDict (LRUCache CID RecvQ)

recvQDictSize :: Int
recvQDictSize = 100

emptyRecvQDict :: RecvQDict
emptyRecvQDict = RecvQDict $ LRUCache.empty recvQDictSize

lookupRecvQDict :: IORef RecvQDict -> CID -> IO (Maybe RecvQ)
lookupRecvQDict ref dcid = do
    RecvQDict c <- readIORef ref
    return $ case LRUCache.lookup dcid c of
        Nothing -> Nothing
        Just q -> Just q

insertRecvQDict :: IORef RecvQDict -> CID -> RecvQ -> IO ()
insertRecvQDict ref dcid q = atomicModifyIORef'' ref ins
  where
    ins (RecvQDict c) = RecvQDict $ LRUCache.insert dcid q c

----------------------------------------------------------------

data Accept = Accept
    { accVersionInfo :: VersionInfo
    , accMyAuthCIDs :: AuthCIDs
    , accPeerAuthCIDs :: AuthCIDs
    , accMySocket :: Socket
    , accPeerInfo :: PeerInfo
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

checkLoop :: TVar ServerState -> STM () -> IO Bool
checkLoop stvar waitsock = atomically $ do
    st <- readTVar stvar
    if st == Stopped
        then
            return False
        else do
            waitsock -- blocking is retry
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
    wait <- waitReadSocketSTM mysock
    handleLogUnit logAction $ loop wait
  where
    loop wait = do
        cont <- checkLoop stvar wait
        when cont $ do
            (peersa, bs, cmsgs, _) <- safeRecv $ NSB.recvMsg mysock 2048 2048 0
            now <- getTimeMicrosecond
            let send' b = void $ NSB.sendMsg mysock peersa [b] cmsgs 0
                -- cf: greaseQuicBit $ getMyParameters conn
                quicBit = greaseQuicBit $ scParameters conf
            cpckts <- decodeCryptPackets bs (not quicBit)
            let bytes = BS.length bs
                peerInfo = PeerInfo peersa cmsgs
                switch = dispatch d conf forkConnection logAction mysock peerInfo send' bytes now
            mapM_ switch cpckts
            loop wait

    doDebug = isJust $ scDebugLog conf
    logAction msg
        | doDebug = stdoutLogger ("dispatch(er): " <> msg)
        | otherwise = return ()

    safeRecv rcv = do
        ex <- E.try $ windowsThreadBlockHack rcv
        case ex of
            Right x -> return x
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
    -> PeerInfo
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
    peerInfo
    send'
    bytes
    tim
    (cpkt@(CryptPacket (Initial peerVer dCID sCID token) _), lvl, siz)
        | bytes < defaultQUICPacketSize = do
            logAction $ "too small " <> bhow bytes <> ", " <> bhow peerInfo
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
        pushToAcceptQ myAuthCIDs peerAuthCIDs key addrValid = do
            mq <- lookupRecvQDict srcTable key
            case mq of
                Just q -> writeRecvQ q $ mkReceivedPacket cpkt tim siz lvl
                Nothing -> do
                    q <- newRecvQ
                    insertRecvQDict srcTable key q
                    writeRecvQ q $ mkReceivedPacket cpkt tim siz lvl
                    let reg = registerConnectionDict dstTable
                        unreg = unregisterConnectionDict dstTable
                        acc =
                            Accept
                                { accVersionInfo = VersionInfo peerVer myVersions
                                , accMyAuthCIDs = myAuthCIDs
                                , accPeerAuthCIDs = peerAuthCIDs
                                , accMySocket = mysock
                                , accPeerInfo = peerInfo
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
            pushToAcceptQ myAuthCIDs peerAuthCIDs dCID addrValid
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
            pushToAcceptQ myAuthCIDs peerAuthCIDs o True
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
    _peerInfo
    _
    _
    tim
    (cpkt@(CryptPacket (RTT0 _ dCID _) _), lvl, siz) = do
        mq <- lookupRecvQDict srcTable dCID
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
    peerInfo
    _
    _
    tim
    (cpkt@(CryptPacket hdr _crypt), lvl, siz) = do
        let dCID = headerMyCID hdr
        mconn <- lookupConnectionDict dstTable dCID
        case mconn of
            Nothing -> logAction $ "CID no match: " <> bhow dCID <> ", " <> bhow peerInfo
            Just conn -> do
                void $ setSocket conn mysock
                setPeerInfo conn peerInfo
                writeRecvQ (connRecvQ conn) $ mkReceivedPacket cpkt tim siz lvl

recvServer :: RecvQ -> IO ReceivedPacket
recvServer = readRecvQ
