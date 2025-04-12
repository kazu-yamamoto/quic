{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client.Reader (
    readerClient,
    recvClient,
    ConnectionControl (..),
    controlConnection,
    clientSocket,
) where

import Control.Concurrent
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

-- | readerClient dies when the socket is closed.
readerClient :: Socket -> Connection -> IO ()
readerClient s0 conn = handleLogUnit logAction $ do
    labelMe "readerClient"
    wait
    connected <- getSockConnected conn
    peersa0 <- getPeerInfo conn
    let recv
            | connected = NSB.recv s0 2048
            | otherwise = do
                (bs, peersa) <- NSB.recvFrom s0 2048
                if peersa /= peersa0 then recv else return bs
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
        ito <- readMinIdleTimeout conn
        mbs <- timeout ito "readeClient" recv
        case mbs of
            Nothing -> close s0
            Just bs -> do
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
    rebind conn $ Microseconds 5000 -- nearly 0
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
            rebind conn $ Microseconds 5000000
            -- Sending PathChallenge, RetireConnectionID and NewConnectionID RPT
            validatePath conn mcidinfo
            return True

rebind :: Connection -> Microseconds -> IO ()
rebind conn microseconds = do
    peersa <- getPeerInfo conn
    newSock <- natRebinding peersa
    connected <- getSockConnected conn
    when connected $ connect newSock peersa
    oldSock <- setSocket conn newSock
    let reader = readerClient newSock conn
    forkManaged conn reader
    fire conn microseconds $ close oldSock
