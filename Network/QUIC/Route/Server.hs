{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Route.Server (
    ServerConfig(..)
  , defaultServerConfig
  , ServerRoute(..)
  , RouteTable
  , Accept(..)
  , newServerRoute
  , router
  ) where

import Control.Concurrent.STM
import Data.IORef
import Data.Map (Map)
import qualified Data.Map as M
import Network.ByteOrder
import Network.Socket
import qualified Network.Socket.ByteString as NBS

import Network.QUIC.Config
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Route.Token
import Network.QUIC.TLS
import Network.QUIC.Types

data Accept = Accept CID CID OrigCID SockAddr SockAddr (TQueue CryptPacket) (CID -> IO ()) (CID -> IO ())

data ServerRoute = ServerRoute {
    tokenSecret  :: TokenSecret
  , routeTable   :: IORef RouteTable
  , acceptQueue  :: TQueue Accept
  }

newServerRoute :: IO ServerRoute
newServerRoute = ServerRoute <$> generateTokenSecret <*> newIORef M.empty <*> newTQueueIO

type RouteTable = Map CID (TQueue CryptPacket)

router :: ServerConfig -> ServerRoute -> (Socket, SockAddr) -> IO ()
router conf route (s,mysa) = forever $ do
    (bs0,peersa) <- recv
    (pkt, bs0RTT) <- decodePacket bs0
    let send bs = void $ NBS.sendTo s bs peersa
    dispatch conf route pkt mysa peersa send bs0RTT
  where
    recv = NBS.recvFrom s 2048

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
-- For the first fragment, handshake would success if others are retransmitted.
-- For the other fragments, handshake will fail since offset is not 0.
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
          Nothing -> do
              newdCID <- newCID
              if scRequireRetry then do
                  let retryToken = RetryToken currentDraft newdCID sCID dCID
                  newtoken <- encryptRetryToken tokenSecret retryToken
                  bss <- encodeRetryPacket $ RetryPacket currentDraft sCID newdCID dCID newtoken
                  send bss
                else do
                  q <- newTQueueIO
                  -- fixme: check listen length
                  atomically $ writeTQueue q cpkt
                  when (bs0RTT /= "") $ do
                      (PacketIC cpktRTT0, _) <- decodePacket bs0RTT
                      atomically $ writeTQueue q cpktRTT0
                  let ent = Accept newdCID sCID (OCFirst dCID) mysa peersa q (registerRoute routeTable q) (unregisterRoute routeTable)
                  atomically $ writeTQueue acceptQueue ent
          Just q -> atomically $ writeTQueue q cpkt -- resend packets
  | otherwise = do
        mretryToken <- decryptRetryToken tokenSecret token
        case mretryToken of
          Nothing -> return ()
          Just RetryToken{..} -> do
              when (tokenVersion /= ver) $ error "dispatch: fixme"
              when (dCID /= localCID) $ error "dispatch: fixme"
              when (sCID /= remoteCID) $ error "dispatch: fixme"
              q <- newTQueueIO
              -- fixme: check listen length
              atomically $ writeTQueue q cpkt
              let ent = Accept dCID sCID (OCRetry origLocalCID) mysa peersa q  (registerRoute routeTable q) (unregisterRoute routeTable)
              atomically $ writeTQueue acceptQueue ent
dispatch _ ServerRoute{..} (PacketIC (CryptPacket (Short dCID) _)) _ _ _ _ = do
    mroute <- lookupRoute routeTable dCID
    case mroute of
      Nothing -> pathValidation
      Just _  -> return () -- connected socket is done? No. fixme.
dispatch _ _ _ _ _ _ _ = return ()
