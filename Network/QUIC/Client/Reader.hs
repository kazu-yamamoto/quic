{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client.Reader (
    readerClient,
    recvClient,
    ConnectionControl (..),
    controlConnection,
) where

import Data.List (intersect)
import Network.Socket (getSocketName)
import Network.UDP
import UnliftIO.Concurrent
import qualified UnliftIO.Exception as E

import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Crypto
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Recovery
import Network.QUIC.Types hiding (localCID, remoteCID)

-- | readerClient dies when the socket is closed.
readerClient :: UDPSocket -> Connection -> IO ()
readerClient cs0@(UDPSocket s0 _ _) conn = handleLogUnit logAction $ do
    wait
    loop
  where
    wait = do
        bound <- E.handleAny (\_ -> return False) $ do
            _ <- getSocketName s0
            return True
        unless bound $ do
            yield
            wait
    loop = do
        ito <- readMinIdleTimeout conn
        mbs <-
            timeout ito "readeClient" $
                recv cs0
        case mbs of
            Nothing -> close cs0
            Just bs -> do
                now <- getTimeMicrosecond
                pkts <- decodePackets bs False
                mapM_ (putQ now) pkts
                loop
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
    putQ t (PacketIC pkt lvl siz) = writeRecvQ (connRecvQ conn) $ mkReceivedPacket pkt t siz lvl
    putQ t (PacketIR pkt@(RetryPacket ver dCID sCID token ex)) = do
        qlogReceived conn pkt t
        ok <- checkCIDs conn dCID ex
        when ok $ do
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

controlConnection' :: Connection -> ConnectionControl -> IO Bool
controlConnection' conn ChangeServerCID = do
    mn <- timeout (Microseconds 1000000) "controlConnection' 1" $ waitPeerCID conn -- fixme
    case mn of
        Nothing -> return False
        Just (CIDInfo n _ _) -> do
            sendFrames conn RTT1Level [RetireConnectionID n]
            return True
controlConnection' conn ChangeClientCID = do
    cidInfo <- getNewMyCID conn
    x <- (+ 1) <$> getMyCIDSeqNum conn
    sendFrames conn RTT1Level [NewConnectionID cidInfo x]
    return True
controlConnection' conn NATRebinding = do
    rebind conn $ Microseconds 5000 -- nearly 0
    return True
controlConnection' conn ActiveMigration = do
    mn <- timeout (Microseconds 1000000) "controlConnection' 2" $ waitPeerCID conn -- fixme
    case mn of
        Nothing -> return False
        mcidinfo -> do
            rebind conn $ Microseconds 5000000
            validatePath conn mcidinfo
            return True

rebind :: Connection -> Microseconds -> IO ()
rebind conn microseconds = do
    cs0 <- getSocket conn
    cs <- natRebinding cs0
    cs0' <- setSocket conn cs
    let reader = readerClient cs conn
    forkIO reader >>= addReader conn
    -- Using cs0' just in case.
    fire conn microseconds $ close cs0'
