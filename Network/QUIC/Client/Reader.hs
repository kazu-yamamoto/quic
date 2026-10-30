{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client.Reader (
    readerClient,
    rebind,
    recvClient,
    ConnectionControl (..),
    controlConnection,
    clientSocket,
) where

import Control.Concurrent
import Control.Concurrent.STM
import Data.Functor (($>))
import qualified Control.Monad.STM as STM
import qualified Control.Exception as E
import Data.List (intersect)
import Network.Socket (Socket, close, connect, getSocketName)
import qualified Network.Socket.ByteString as NSB

import Network.QUIC.Common
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Crypto
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Recovery
import Network.QUIC.Socket
import Network.QUIC.Types

-- What ended a wait in 'readerClient'.
data ReaderEnd = Retired | TimedOut

-- | The reader of a client's socket.  It returns when the socket is
--   retired, which is how 'rebind' ends the reader of the socket it
--   replaced, and when the connection has been idle for too long.
--
--   Nothing is closed and nothing is thrown to make it return: the receive
--   and both of those are waited for at once.  A socket retired by 'rebind'
--   is closed here rather than by the caller, which cannot see when this
--   has returned and would be closing it under a reader.
readerClient :: TVar Bool -> Socket -> Connection -> IO ()
readerClient retired s0 conn = handleLogUnit logAction $ do
    labelMe "readerClient"
    wait
    connected <- getSockConnected conn
    peersa0 <- peerSockAddr <$> getPathInfo conn
    let recv giveUp
            | connected = NSB.recvWith s0 2048 giveUp
            | otherwise = do
                r <- NSB.recvFromWith s0 2048 giveUp
                case r of
                    Left a -> return $ Left a
                    Right (bs, peersa)
                        | peersa /= peersa0 -> recv giveUp
                        | otherwise -> return $ Right bs
    loop recv
  where
    wait = do
        bound <- E.handle (throughAsync (return False)) $ do
            _ <- getSocketName s0
            return True
        unless bound $ do
            yield
            wait
    loop recv = do
        Microseconds ito <- readMinIdleTimeout conn
        expired <- registerDelay ito
        ebs <-
            recv $
                ((readTVar retired >>= STM.check) $> Retired)
                    `orElse` ((readTVar expired >>= STM.check) $> TimedOut)
        case ebs of
            -- 'rebind' swapped this socket out before retiring it, so the
            -- sender is the only thread which can still be inside a call
            -- on it: it is left for the sender to close, said here, where
            -- it is known that this reader has left it.  'killReaders' did
            -- not swap, and the closer still reads and sends on it.
            Left Retired -> do
                current <- getSocketRetire conn
                when (current /= retired) $ retireSocket conn s0
            Left TimedOut -> close s0
            Right bs -> do
                now <- getTimeMicrosecond
                let quicBit = greaseQuicBit $ getMyParameters conn
                pkts <- decodePackets bs (not quicBit)
                mapM_ (putQ now) pkts
                loop recv
    logAction msg = connDebugLog conn ("debug: readerClient: " <> msg)
    putQ _ (PacketIB BrokenPacket _) = return ()
    putQ t (PacketIV pkt@(VersionNegotiationPacket dCID sCID peerVers)) = do
        qlogReceived conn pkt t
        myVerInfo <- getVersionInfo conn
        let myVer = chosenVersion myVerInfo
            myVers0 = otherVersions myVerInfo
        -- ignoring VN if the original version is included.
        when (myVer `notElem` peerVers && Negotiation `notElem` peerVers) $ do
            ok <- checkCIDs conn dCID (Left sCID)
            let myVers = filter (not . isGreasingVersion) myVers0
                nextVerInfo = case myVers `intersect` peerVers of
                    vers@(ver : _) | ok -> VersionInfo ver vers
                    _ -> brokenVersionInfo
            E.throwTo (mainThreadId conn) $ VerNego nextVerInfo
    putQ t (PacketIC pkt@(CryptPacket hdr crypt) lvl siz) = do
        let cid = headerMyCID hdr
        included <- myCIDsInclude conn cid
        case included of
            Just _ -> writeRecvQ (connRecvQ conn) $ mkReceivedPacket pkt t siz lvl
            Nothing -> case decodeStatelessResetToken (cryptPacket crypt) of
                Just token -> do
                    isStatelessReset <- isStatelessRestTokenValid conn token
                    -- Our client does not send a stateless reset:
                    -- 1) Stateless reset token is not generated for
                    --    the my first CID.
                    -- 2) It's unlikely that QUIC packets are delivered
                    --    to a new UDP port when out client is rebooted.
                    when isStatelessReset $ do
                        qlogReceived conn StatelessReset t
                        connDebugLog conn "debug: connection is reset statelessly"
                        E.throwTo (mainThreadId conn) ConnectionIsReset
                _ -> return () -- really invalid, just ignore
    putQ t (PacketIR pkt@(RetryPacket ver dCID sCID token ex)) = do
        qlogReceived conn pkt t
        ok <- checkCIDs conn dCID ex
        when ok $ do
            -- Re-creating peer's CIDDB with peer's CID.
            resetPeerCID conn sCID
            setPeerAuthCIDs conn $ \auth -> auth{retrySrcCID = Just sCID}
            initializeCoder conn InitialLevel $ initialSecrets ver sCID
            setToken conn token
            setRetried conn True
            releaseByRetry (connLDCC conn) >>= mapM_ put
      where
        put ppkt = putOutput conn $ OutRetrans ppkt

checkCIDs :: Connection -> CID -> Either CID (ByteString, ByteString) -> IO Bool
checkCIDs conn dCID (Left sCID) = do
    localCID <- getMyCID conn
    remoteCID <- getPeerCID conn
    return (dCID == localCID && sCID == remoteCID)
checkCIDs conn dCID (Right (pseudo0, tag)) = do
    localCID <- getMyCID conn
    remoteCID <- getPeerCID conn
    ver <- getVersion conn
    let ok = calculateIntegrityTag ver remoteCID pseudo0 == tag
    return (dCID == localCID && ok)

recvClient :: RecvQ -> IO ReceivedPacket
recvClient = readRecvQ

----------------------------------------------------------------

-- | How to control a connection.
data ConnectionControl
    = ChangeServerCID
    | ChangeClientCID
    | NATRebinding
    | ActiveMigration
    deriving (Eq, Show)

controlConnection :: Connection -> ConnectionControl -> IO Bool
controlConnection conn typ
    | isClient conn = do
        waitEstablished conn
        controlConnection' conn typ
    | otherwise = return False

----------------------------------------------------------------
-- ping: NewConnectionID(retirePriorTo), pong: RetireConnectionID
--
-- RFC 9000 Sec 5.1.2: Upon receipt of an increased Retire Prior To
-- field, the peer MUST stop using the corresponding connection IDs
-- and retire them with RETIRE_CONNECTION_ID frames before adding the
-- newly provided connection ID to the set of active connection IDs.
--
-- An endpoint MUST NOT forget a connection ID without retiring it.
--
----------------------------------------------------------------
-- ping: RetireConnectionID, pong: NewConnectionID
--
-- RFC 9000 Sec 5.1.1: An endpoint SHOULD supply a new connection ID
-- when the peer retires a connection ID.
-- RFC 9000 Sec 5.1.2: Sending a RETIRE_CONNECTION_ID frame indicates
-- that the connection ID will not be used again and requests that the
-- peer replace it with a new connection ID using a NEW_CONNECTION_ID
-- frame.
--
----------------------------------------------------------------
-- ping: PathChallenge, pong: PathResponse
--
-- RFC 9000 Sec 8.2.2: On receiving a PATH_CHALLENGE frame, an
-- endpoint MUST respond by echoing the data contained in the
-- PATH_CHALLENGE frame in a PATH_RESPONSE frame.
--
controlConnection' :: Connection -> ConnectionControl -> IO Bool
----------------------------------------------------------------
-- ChangeServerCID (-M)
--
-- Co -> Sn: RetireConnectionID(So)
-- Cn <- Sn: NewConnectionID (receiver)
controlConnection' conn ChangeServerCID = do
    mn <- timeout (Microseconds 1000000) "controlConnection' 1" $ waitPeerCID conn -- fixme
    case mn of
        Nothing -> return False
        Just cidInfo -> do
            let seqNum = cidInfoSeq cidInfo
            retirePeerCID conn seqNum
            -- Client tells "I don't use this CID of yours".
            sendFrames conn RTT1Level [RetireConnectionID seqNum]
            return True
----------------------------------------------------------------
-- ChangeClientCID (-N)
--
-- Co -> So: NewConnectionID(retirePriorTo Co)
-- Cn <- Sn: RetireConnectionID(Co) (processFrame)
controlConnection' conn ChangeClientCID = do
    -- checkPeerCIDCapacity is not necessary beucase one CID is
    -- retired.
    cidInfo <- getNewMyCID conn
    retirePriorTo' <- (+ 1) <$> getMyCIDSeqNum conn
    setMyRetirePriorTo conn retirePriorTo' -- just for record
    writeIORef (sentRetirePriorTo conn) True
    -- Client tells "My CIDs less than retirePriorTo should be retired".
    sendFrames conn RTT1Level [NewConnectionID cidInfo retirePriorTo']
    return True
----------------------------------------------------------------
-- NATRebinding (-B)
--
-- <local port change>
-- So -> Co: PathChallenge (validatePath)
-- Co -> So: PathResponse (processFrame)
controlConnection' conn NATRebinding = do
    rebind conn
    return True
----------------------------------------------------------------
-- ActiveMigration (-A)
--
-- <local port change>
-- Co -> Sn: NewConnectionID(retirePriorTo Co), RetireConnectionID(So), PathChallenge (validatePath)
-- Cn <- Sn: RetireConnectionID(Co), PathChallenge (validatePath)
-- Cn <- Sn: NewConnectionID (receiver)
-- Cn -> Sn: PathResponse (processFrame)
-- Cn <- Sn: PathResponse (processFrame)
controlConnection' conn ActiveMigration = do
    -- Changing peer CID
    mn <- timeout (Microseconds 1000000) "controlConnection' 2" $ waitPeerCID conn -- fixme
    case mn of
        Nothing -> return False
        mcidinfo -> do
            peersa <- peerSockAddr <$> getPathInfo conn
            rebind conn
            -- Sending PathChallenge, RetireConnectionID and NewConnectionID RPT
            pathInfo <- newPathInfo peersa
            addPathInfo conn pathInfo
            validatePath conn pathInfo mcidinfo
            return True

rebind :: Connection -> IO ()
rebind conn = do
    peersa <- peerSockAddr <$> getPathInfo conn
    newSock <- natRebinding peersa
    connected <- getSockConnected conn
    when connected $ connect newSock peersa
    newRetired <- newTVarIO False
    (_, oldRetired) <- swapSocket conn newSock newRetired
    (forkManaged conn "QUIC reader" $ readerClient newRetired newSock conn)
        `E.finally` do
            -- Telling the old reader to go rather than closing the socket
            -- under it: a close ends a thread blocked on a descriptor only
            -- because the event manager says so.  The reader leaves it for
            -- the sender instead.  Said even if the fork above failed,
            -- since the old socket is not this connection's any more
            -- either way.
            atomically $ writeTVar oldRetired True
