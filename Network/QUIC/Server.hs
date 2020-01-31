{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Server (
    ServerRoute(..)
  , newServerRoute
  , router
  , RouteTable
  , AcceptQ
  , Accept(..)
  , readAcceptQ
  , ServerRecvQ
  , RecvCryptPacket(..)
  , readServerRecvQ
  , writeServerRecvQ
  , recvServer
  , readerServer
  , CT.killTokenManager
  ) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Crypto.Token as CT
import Data.Hourglass (Seconds(..), timeDiff)
import Data.IORef
import Data.Map (Map)
import qualified Data.Map as M
import Network.ByteOrder
import Network.Socket
import qualified Network.Socket.ByteString as NSB
import Time.System (timeCurrent)

import Network.QUIC.Config
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Socket
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

data Accept = Accept Version CID CID OrigCID SockAddr SockAddr ServerRecvQ (CID -> IO ()) (CID -> IO ()) Bool -- retried

data ServerRoute = ServerRoute {
    tokenMgr    :: CT.TokenManager
  , routeTable  :: IORef RouteTable
  , acceptQueue :: AcceptQ
  }

newServerRoute :: IO ServerRoute
newServerRoute = ServerRoute <$> CT.spawnTokenManager CT.defaultConfig <*> newIORef M.empty <*> newAcceptQ

type RouteTable = Map CID ServerRecvQ

----------------------------------------------------------------

newtype AcceptQ = AcceptQ (TQueue Accept)

newAcceptQ :: IO AcceptQ
newAcceptQ = AcceptQ <$> newTQueueIO

readAcceptQ :: AcceptQ -> IO Accept
readAcceptQ (AcceptQ q) = atomically $ readTQueue q

writeAcceptQ :: AcceptQ -> Accept -> IO ()
writeAcceptQ (AcceptQ q) x = atomically $ writeTQueue q x

----------------------------------------------------------------

data RecvCryptPacket = Through CryptPacket | NATRebinding CryptPacket SockAddr

newtype ServerRecvQ = ServerRecvQ (TQueue RecvCryptPacket)

newServerRecvQ :: IO ServerRecvQ
newServerRecvQ = ServerRecvQ <$> newTQueueIO

readServerRecvQ :: ServerRecvQ -> IO RecvCryptPacket
readServerRecvQ (ServerRecvQ q) = atomically $ readTQueue q

writeServerRecvQ :: ServerRecvQ -> RecvCryptPacket -> IO ()
writeServerRecvQ (ServerRecvQ q) x = atomically $ writeTQueue q x

----------------------------------------------------------------

router :: ServerConfig -> ServerRoute -> (Socket, SockAddr) -> IO ()
router conf route (s,mysa) = handle handler $ do
    let (opt,_cmsgid) = case mysa of
          SockAddrInet{}  -> (RecvIPv4PktInfo, CmsgIdIPv4PktInfo)
          SockAddrInet6{} -> (RecvIPv6PktInfo, CmsgIdIPv6PktInfo)
          _               -> error "router"
    setSocketOption s opt 1
    handle handler $ forever $ do
        (peersa, bs0, _cmsgs, _) <- recv
        -- macOS overrides the local address of the socket
        -- if in_pktinfo is used.
#if defined(darwin_HOST_OS)
        let cmsgs' = []
#else
        let cmsgs' = filterCmsg _cmsgid _cmsgs
#endif
        (pkt, bs0RTT) <- decodePacket bs0
        let send bs = void $ NSB.sendMsg s peersa [bs] cmsgs' 0
        dispatch conf route pkt mysa peersa send bs0RTT
  where
    recv = NSB.recvMsg s 2048 64 0

----------------------------------------------------------------

lookupRoute :: IORef RouteTable -> CID -> IO (Maybe ServerRecvQ)
lookupRoute tbl cid = M.lookup cid <$> readIORef tbl

registerRoute :: IORef RouteTable -> ServerRecvQ -> CID -> IO ()
registerRoute tbl q cid = atomicModifyIORef' tbl $ \rt' -> (M.insert cid q rt', ())

unregisterRoute :: IORef RouteTable -> CID -> IO ()
unregisterRoute tbl cid = atomicModifyIORef' tbl $ \rt' -> (M.delete cid rt', ())

-- If client initial is fragmented into multiple packets,
-- there is no way to put the all packets into a single queue.
-- Rather, each fragment packet is put into its own queue.
-- For the first fragment, handshake would successif others are
-- retransmitted.
-- For the other fragments, handshake will fail since its socket
-- cannot be connected.
dispatch :: ServerConfig -> ServerRoute -> PacketI -> SockAddr -> SockAddr -> (ByteString -> IO ()) -> ByteString -> IO ()
dispatch ServerConfig{..} ServerRoute{..}
         (PacketIC cpkt@(CryptPacket (Initial ver dCID sCID token) _))
         mysa peersa send bs0RTT
  | ver `notElem` confVersions scConfig = do
        bss <- encodeVersionNegotiationPacket $ VersionNegotiationPacket sCID dCID (confVersions scConfig)
        send bss
  | token == "" = do
        mroute <- lookupRoute routeTable dCID
        case mroute of
          Nothing
            | scRequireRetry -> sendRetry
            | otherwise      -> pushToAcceptQ1
          Just q -> writeServerRecvQ q (Through cpkt) -- resend packets
  | otherwise = do
        mct <- decryptToken tokenMgr token
        case mct of
          Just ct
            | isRetryToken ct -> do
                  ok <- isRetryTokenValid ct
                  if ok then pushToAcceptQ2 ct else sendRetry
            | otherwise -> do
                  mroute <- lookupRoute routeTable dCID
                  case mroute of
                    Nothing -> pushToAcceptQ1
                    Just q -> writeServerRecvQ q (Through cpkt) -- resend packets
          _ -> sendRetry
  where
    pushToAcceptQ d s oc retried = do
        q <- newServerRecvQ
        -- fixme: check listen length
        writeServerRecvQ q (Through cpkt)
        let ent = Accept ver d s oc mysa peersa q (registerRoute routeTable q) (unregisterRoute routeTable) retried
        writeAcceptQ acceptQueue ent
        return q
    pushToAcceptQ1 = do
        newdCID <- newCID
        q <- pushToAcceptQ newdCID sCID (OCFirst dCID) False
        when (bs0RTT /= "") $ do
            (PacketIC cpktRTT0, _) <- decodePacket bs0RTT
            writeServerRecvQ q (Through cpktRTT0)
    pushToAcceptQ2 (CryptoToken _ _ (Just (_,_,o))) = do
        _ <- pushToAcceptQ dCID sCID (OCRetry o) True
        return ()
    pushToAcceptQ2 _ = return ()
    isRetryTokenValid (CryptoToken tver tim (Just (l,r,_))) = do
        tim0 <- timeCurrent
        let diff = tim `timeDiff` tim0
        return $ tver == ver
              && diff <= Seconds 30 -- fixme
              && dCID == l
              && sCID == r
    isRetryTokenValid _ = return False
    sendRetry = do
        newdCID <- newCID
        retryToken <- generateRetryToken ver newdCID sCID dCID
        newtoken <- encryptToken tokenMgr retryToken
        bss <- encodeRetryPacket $ RetryPacket ver sCID newdCID newtoken (Left dCID)
        send bss
dispatch _ ServerRoute{..} (PacketIC cpkt@(CryptPacket (Short dCID) _)) _ peersa _ _ = do
    -- fixme: packets for closed connections also match here.
    mroute <- lookupRoute routeTable dCID
    case mroute of
      Nothing -> do
          putStrLn "No routing"
          print dCID
          print peersa
      Just q  -> do
          putStrLn $ "NAT rebiding to " ++ show peersa
          writeServerRecvQ q (NATRebinding cpkt peersa)
dispatch _ _ (PacketIB _)  _ _ _ _ = print BrokenPacket
dispatch _ _ _ _ _ _ _ = return () -- throwing away

----------------------------------------------------------------

-- readerServer dies when the socket is closed.
readerServer :: Socket -> ServerRecvQ -> IO ()
readerServer s q = handle handler $ forever $ do
    pkts <- NSB.recv s 2048 >>= decodeCryptPackets
    mapM (\pkt -> writeServerRecvQ q (Through pkt)) pkts

recvServer :: SockAddr -> ServerRecvQ -> IORef (Socket, SockAddr)
           -> IO CryptPacket
recvServer mysa q sref = do
    rp <- readServerRecvQ q
    case rp of
      Through pkt -> return pkt
      NATRebinding pkt peersa1 -> do
          (s,peersa) <- readIORef sref
          when (peersa /= peersa1) $ do
              s1 <- udpServerConnectedSocket mysa peersa1
              writeIORef sref (s1,peersa1)
              void $ forkIO $ readerServer s1 q
              close s
          return pkt
