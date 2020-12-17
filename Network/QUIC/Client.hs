{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client (
    readerClient
  , recvClient
  , Migration(..)
  , migration
  ) where

import Control.Concurrent
import qualified Control.Exception as E
import qualified Data.ByteString as BS
import Data.List (intersect)
import Network.Socket (Socket, getPeerName, close)
import qualified Network.Socket.ByteString as NSB

import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Recovery
import Network.QUIC.Socket
import Network.QUIC.TLS
import Network.QUIC.Timeout
import Network.QUIC.Types

-- | readerClient dies when the socket is closed.
readerClient :: ThreadId -> [Version] -> Socket -> RecvQ -> Connection -> IO ()
readerClient tid myVers s q conn = handleLog logAction $ forever $ do
    bs <- NSB.recv s maximumUdpPayloadSize
    now <- getTimeMicrosecond
    let udpPayloadSize = BS.length bs
    addRxBytes conn udpPayloadSize
    pkts <- decodePackets bs
    mapM_ (putQ now udpPayloadSize) pkts
  where
    logAction msg = connDebugLog conn ("readerClient: " <> msg)
    putQ _ _ (PacketIB BrokenPacket) = return ()
    putQ t _ (PacketIV pkt@(VersionNegotiationPacket dCID sCID peerVers)) = do
        qlogReceived conn pkt t
        mver <- case myVers of
          []  -> return Nothing
          [_] -> return Nothing
          _:myVers' -> case myVers' `intersect` peerVers of
                  []    -> return Nothing
                  ver:_ -> do
                      ok <- checkCIDs conn dCID (Left sCID)
                      return $ if ok then Just ver else Nothing
        killHandshaker conn
        case mver of
          Nothing  -> E.throwTo tid VersionNegotiationFailed
          Just ver -> E.throwTo tid $ NextVersion ver
    putQ t z (PacketIC pkt lvl) = writeRecvQ q $ mkReceivedPacket pkt t z lvl
    putQ t _ (PacketIR pkt@(RetryPacket ver dCID sCID token ex)) = do
        qlogReceived conn pkt t
        ok <- checkCIDs conn dCID ex
        when ok $ do
            resetPeerCID conn sCID
            setPeerAuthCIDs conn $ \auth -> auth { retrySrcCID  = Just sCID }
            initializeCoder conn InitialLevel $ initialSecrets ver sCID
            setToken conn token
            setRetried conn True
            releaseByRetry (connLDCC conn) >>= mapM_ put
      where
        put ppkt = putOutput conn $ OutRetrans ppkt

checkCIDs :: Connection -> CID -> Either CID (ByteString,ByteString) -> IO Bool
checkCIDs conn dCID (Left sCID) = do
    localCID <- getMyCID conn
    remoteCID <- getPeerCID conn
    return (dCID == localCID && sCID == remoteCID)
checkCIDs conn dCID (Right (pseudo0,tag)) = do
    localCID <- getMyCID conn
    remoteCID <- getPeerCID conn
    ver <- getVersion conn
    let ok = calculateIntegrityTag ver remoteCID pseudo0 == tag
    return (dCID == localCID && ok)

recvClient :: RecvQ -> IO ReceivedPacket
recvClient = readRecvQ

----------------------------------------------------------------

data Migration = ChangeServerCID
               | ChangeClientCID
               | NATRebinding
               | MigrateTo -- SockAddr
               deriving (Eq, Show)

-- | Migrating.
migration :: Connection -> Migration -> IO Bool
migration conn typ
  | isClient conn = do
        waitEstablished conn
        migrationClient conn typ
  | otherwise     = return False

migrationClient :: Connection -> Migration -> IO Bool
migrationClient conn ChangeServerCID = do
    mn <- timeout (Microseconds 1000000) $ choosePeerCID conn -- fixme
    case mn of
      Nothing              -> return False
      Just (CIDInfo n _ _) -> do
          let frames = [RetireConnectionID n]
          putOutput conn $ OutControl RTT1Level frames
          return True
migrationClient conn ChangeClientCID = do
    cidInfo <- getNewMyCID conn
    x <- (+1) <$> getMyCIDSeqNum conn
    let frames = [NewConnectionID cidInfo x]
    putOutput conn $ OutControl RTT1Level frames
    return True
migrationClient conn NATRebinding = do
    rebind conn $ Microseconds 5000 -- nearly 0
    return True
migrationClient conn MigrateTo = do
    mn <- timeout (Microseconds 1000000) $ choosePeerCID conn -- fixme
    case mn of
      Nothing  -> return False
      mcidinfo -> do
          rebind conn $ Microseconds 5000000
          validatePath conn mcidinfo
          return True

rebind :: Connection -> Microseconds -> IO ()
rebind conn microseconds = do
    (s0,q) <- getSockInfo conn
    s1 <- getPeerName s0 >>= udpNATRebindingSocket
    setSockInfo conn (s1,q)
    v <- getVersion conn
    mytid <- myThreadId
    void $ forkIO $ readerClient mytid [v] s1 q conn -- versions are dummy
    fire microseconds $ close s0
