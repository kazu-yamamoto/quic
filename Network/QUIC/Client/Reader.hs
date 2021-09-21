{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client.Reader (
    readerClient
  , recvClient
  , ConnectionControl(..)
  , controlConnection
  , migrate
  ) where

import Control.Concurrent
import qualified Data.ByteString as BS
import Data.List (intersect)
import Network.Socket (Socket, getPeerName, close)
import qualified Network.Socket.ByteString as NSB
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
import Network.QUIC.Socket
import Network.QUIC.Types

-- | readerClient dies when the socket is closed.
readerClient :: [Version] -> Socket -> Connection -> IO ()
readerClient myVers s0 conn = handleLogUnit logAction $ do
    getServerAddr conn >>= loop
  where
    loop msa0 = do
        ito <- readMinIdleTimeout conn
        mbs <- timeout ito $ do
            case msa0 of
              Nothing  ->     NSB.recv     s0 maximumUdpPayloadSize
              Just sa0 -> do
                  (bs, sa) <- NSB.recvFrom s0 maximumUdpPayloadSize
                  return $ if sa == sa0 then bs else ""
        case mbs of
          Nothing -> close s0
          Just "" -> loop msa0
          Just bs -> do
            now <- getTimeMicrosecond
            let bytes = BS.length bs
            addRxBytes conn bytes
            pkts <- decodePackets bs
            mapM_ (putQ now bytes) pkts
            loop msa0
    logAction msg = connDebugLog conn ("debug: readerClient: " <> msg)
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
        E.throwTo (mainThreadId conn) $ VerNego mver
    putQ t z (PacketIC pkt lvl) = writeRecvQ (connRecvQ conn) $ mkReceivedPacket pkt t z lvl
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

-- | How to control a connection.
data ConnectionControl = ChangeServerCID
                       | ChangeClientCID
                       | NATRebinding
                       | ActiveMigration
                       deriving (Eq, Show)

-- | Creating a new socket and execute a path validation
--   with a new connection ID. Typically, this is used
--   for migration in the case where 'ccAutoMigration' is 'False'.
--   But this can also be used even when the value is 'True'.
migrate :: Connection -> IO Bool
migrate conn = controlConnection conn ActiveMigration

controlConnection :: Connection -> ConnectionControl -> IO Bool
controlConnection conn typ
  | isClient conn = do
        waitEstablished conn
        controlConnection' conn typ
  | otherwise     = return False

controlConnection' :: Connection -> ConnectionControl -> IO Bool
controlConnection' conn ChangeServerCID = do
    mn <- timeout (Microseconds 1000000) $ waitPeerCID conn -- fixme
    case mn of
      Nothing              -> return False
      Just (CIDInfo n _ _) -> do
          sendFrames conn RTT1Level [RetireConnectionID n]
          return True
controlConnection' conn ChangeClientCID = do
    cidInfo <- getNewMyCID conn
    x <- (+1) <$> getMyCIDSeqNum conn
    sendFrames conn RTT1Level [NewConnectionID cidInfo x]
    return True
controlConnection' conn NATRebinding = do
    rebind conn $ Microseconds 5000 -- nearly 0
    return True
controlConnection' conn ActiveMigration = do
    mn <- timeout (Microseconds 1000000) $ waitPeerCID conn -- fixme
    case mn of
      Nothing  -> return False
      mcidinfo -> do
          rebind conn $ Microseconds 5000000
          validatePath conn mcidinfo
          return True

rebind :: Connection -> Microseconds -> IO ()
rebind conn microseconds = do
    s0:_ <- getSockets conn
    msa0 <- getServerAddr conn
    s1 <- case msa0 of
      Nothing  -> getPeerName s0 >>= udpNATRebindingConnectedSocket
      Just sa0 -> udpNATRebindingSocket sa0
    _ <- addSocket conn s1
    v <- getVersion conn
    let reader = readerClient [v] s1 conn -- versions are dummy
    forkIO reader >>= addReader conn
    fire conn microseconds $ close s0
