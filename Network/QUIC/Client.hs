{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client (
    readerClient
  , recvClient
  , Migration(..)
  , migration
  ) where

import Control.Concurrent
import Network.Socket (Socket, getPeerName, close)
import qualified Network.Socket.ByteString as NSB

import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Socket
import Network.QUIC.TLS
import Network.QUIC.Timeout
import Network.QUIC.Types

-- | readerClient dies when the socket is closed.
readerClient :: [Version] -> Socket -> RecvQ -> Connection -> IO ()
readerClient myVers s q conn = handleLog logAction $ forever $ do
    pkts <- NSB.recv s 2048 >>= decodePackets
    mapM_ putQ pkts
  where
    logAction msg = connDebugLog conn ("readerClient: " ++ msg)
    putQ (PacketIB BrokenPacket) = return ()
    putQ (PacketIV pkt@(VersionNegotiationPacket dCID sCID peerVers)) = do
        qlogReceived conn pkt
        mver <- case myVers `intersect` peerVers of
                  []    -> return Nothing
                  ver:_ -> do
                      ok <- checkCIDs conn dCID (Left sCID)
                      return $ if ok then Just ver else Nothing
        case mver of
          Nothing  -> return ()
          Just ver -> setNextVersion conn ver
        putCrypto conn $ InpVersion mver
    putQ (PacketIC pkt) = writeRecvQ q pkt
    putQ (PacketIR pkt@(RetryPacket ver dCID sCID token ex)) = do
        qlogReceived conn pkt
        ok <- checkCIDs conn dCID ex
        when ok $ do
            resetPeerCID conn sCID
            setInitialSecrets conn $ initialSecrets ver sCID
            setToken conn token
            setRetried conn True
            releaseAllPlainPackets conn >>= mapM_ put
      where
        put ppkt = putOutput conn $ OutPlainPacket ppkt []

checkCIDs :: Connection -> CID -> Either CID (ByteString,ByteString) -> IO Bool
checkCIDs conn dCID (Left sCID) = do
    localCID <- getMyCID conn
    remoteCID <- getPeerCID conn
    return (dCID == localCID && sCID == remoteCID)
checkCIDs conn dCID (Right (pseudo0,tag)) = do
    localCID <- getMyCID conn
    remoteCID <- getPeerCID conn
    let ok = calculateIntegrityTag remoteCID pseudo0 == tag
    return (dCID == localCID && ok)

recvClient :: RecvQ -> IO CryptPacket
recvClient = readRecvQ

----------------------------------------------------------------

data Migration = ChangeServerCID
               | ChangeClientCID
               | NATRebiding
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
    mn <- timeout 1000000 $ choosePeerCID conn -- fixme
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
migrationClient conn NATRebiding = do
    rebind conn 5000 -- nearly 0
    return True
migrationClient conn MigrateTo = do
    mn <- timeout 1000000 $ choosePeerCID conn -- fixme
    case mn of
      Nothing  -> return False
      mcidinfo -> do
          rebind conn 5000000
          validatePath conn mcidinfo
          return True

rebind :: Connection -> Int -> IO ()
rebind conn microseconds = do
    (s0,q) <- getSockInfo conn
    s1 <- getPeerName s0 >>= udpNATRebindingSocket
    setSockInfo conn (s1,q)
    v <- getVersion conn
    void $ forkIO $ readerClient [v] s1 q conn -- versions are dummy
    fire microseconds $ close s0
