{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Server (
    ServerRoute(..)
  , RouteTable
  , Accept(..)
  , newServerRoute
  , router
  , CT.killTokenManager
  ) where

import Control.Concurrent.STM
import qualified Crypto.Token as CT
import Data.Hourglass (Seconds(..), timeDiff)
import Data.IORef
import Data.Map (Map)
import qualified Data.Map as M
import Network.ByteOrder
import Network.Socket
import qualified Network.Socket.ByteString as NBS
import Time.System (timeCurrent)

import Network.QUIC.Config
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.TLS
import Network.QUIC.Types

data Accept = Accept CID CID OrigCID SockAddr SockAddr (TQueue CryptPacket) (CID -> IO ()) (CID -> IO ())

data ServerRoute = ServerRoute {
    tokenMgr    :: CT.TokenManager
  , routeTable  :: IORef RouteTable
  , acceptQueue :: TQueue Accept
  }

newServerRoute :: IO ServerRoute
newServerRoute = ServerRoute <$> CT.spawnTokenManager CT.defaultConfig <*> newIORef M.empty <*> newTQueueIO

type RouteTable = Map CID (TQueue CryptPacket)

router :: ServerConfig -> ServerRoute -> (Socket, SockAddr) -> IO ()
router conf route (s,mysa) = do
    let (opt,_cmsgid) = case mysa of
          SockAddrInet{}  -> (RecvIPv4PktInfo, CmsgIdIPv4PktInfo)
          SockAddrInet6{} -> (RecvIPv6PktInfo, CmsgIdIPv6PktInfo)
          _               -> error "router"
    setSocketOption s opt 1
    forever $ do
        (peersa, bs0, _cmsgs, _) <- recv
        -- macOS overrides the local address of the socket
        -- if in_pktinfo is used.
#if defined(darwin_HOST_OS)
        let cmsgs' = []
#else
        let cmsgs' = filterCmsg _cmsgid _cmsgs
#endif
        (pkt, bs0RTT) <- decodePacket bs0
        let send bs = void $ NBS.sendMsg s peersa [bs] cmsgs' 0
        dispatch conf route pkt mysa peersa send bs0RTT
  where
    recv = NBS.recvMsg s 2048 64 0

pathValidation :: IO ()
pathValidation = undefined

supportedVersions :: [Version]
supportedVersions = [Draft24, Draft23]

----------------------------------------------------------------

lookupRoute :: IORef RouteTable -> CID -> IO (Maybe (TQueue CryptPacket))
lookupRoute tbl cid = M.lookup cid <$> readIORef tbl

registerRoute :: IORef RouteTable -> TQueue CryptPacket -> CID -> IO ()
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
  | ver /= currentDraft && ver `elem` supportedVersions = do
        bss <- encodeVersionNegotiationPacket $ VersionNegotiationPacket sCID dCID (delete ver supportedVersions)
        send bss
  | token == "" = do
        mroute <- lookupRoute routeTable dCID
        case mroute of
          Nothing
            | scRequireRetry -> sendRetry
            | otherwise      -> pushToAcceptQ1
          Just q -> atomically $ writeTQueue q cpkt -- resend packets
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
                    Just q -> atomically $ writeTQueue q cpkt -- resend packets
          _ -> sendRetry
  where
    pushToAcceptQ d s oc = do
        q <- newTQueueIO
        -- fixme: check listen length
        atomically $ writeTQueue q cpkt
        let ent = Accept d s oc mysa peersa q (registerRoute routeTable q) (unregisterRoute routeTable)
        atomically $ writeTQueue acceptQueue ent
        return q
    pushToAcceptQ1 = do
        newdCID <- newCID
        q <- pushToAcceptQ newdCID sCID (OCFirst dCID)
        when (bs0RTT /= "") $ do
            (PacketIC cpktRTT0, _) <- decodePacket bs0RTT
            atomically $ writeTQueue q cpktRTT0
    pushToAcceptQ2 (CryptoToken _ _ (Just (_,_,o))) = do
        _ <- pushToAcceptQ dCID sCID (OCRetry o)
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
        retryToken <- generateRetryToken newdCID sCID dCID
        newtoken <- encryptToken tokenMgr retryToken
        bss <- encodeRetryPacket $ RetryPacket currentDraft sCID newdCID dCID newtoken
        send bss
dispatch _ ServerRoute{..} (PacketIC (CryptPacket (Short dCID) _)) _ _ _ _ = do
    mroute <- lookupRoute routeTable dCID
    case mroute of
      Nothing -> pathValidation
      Just _  -> return () -- connected socket is done? No. fixme.
dispatch _ _ _ _ _ _ _ = return ()
