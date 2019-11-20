{-# LANGUAGE BinaryLiterals #-}
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
import Network.QUIC.Route.Header
import Network.QUIC.Route.Token
import Network.QUIC.TLS
import Network.QUIC.Transport

data Accept = Accept CID CID CID SockAddr SockAddr (TQueue ByteString)

data ServerRoute = ServerRoute {
    tokenSecret  :: TokenSecret
  , routeTable   :: IORef RouteTable
  , acceptQueue  :: TQueue Accept
  }

newServerRoute :: IO ServerRoute
newServerRoute = ServerRoute <$> generateTokenSecret <*> newIORef M.empty <*> newTQueueIO

type RouteTable = Map CID (TQueue ByteString)

router :: ServerConfig -> ServerRoute -> (Socket, SockAddr) -> IO ()
router conf route (s,mysa) = forever $ do
    (bs,peersa) <- recv
    ph <- decodePlainHeader bs
    let send bin = void $ NBS.sendTo s bin peersa
    dispatch conf route ph mysa peersa bs send
  where
    recv = NBS.recvFrom s 2048

pathValidation :: IO ()
pathValidation = undefined

supportedVersions :: [Version]
supportedVersions = [Draft24, Draft23]

----------------------------------------------------------------

-- fixme: deleting unnecessary Entry
dispatch :: ServerConfig -> ServerRoute -> PlainHeader -> SockAddr -> SockAddr -> ByteString -> (ByteString -> IO ()) -> IO ()
dispatch ServerConfig{..} ServerRoute{..} (PHInitial ver dCID sCID token) mysa peersa bs send
  | ver /= currentDraft && ver `elem` supportedVersions = do
        bin <- encodeVersionNegotiation sCID dCID (delete ver supportedVersions)
        send bin
  | token == "" = do
        rt <- readIORef routeTable
        let mroute = M.lookup dCID rt
        case mroute of
          Nothing -> do
              newdCID <- newCID
              if scRequireRetry then do
                  let retryToken = RetryToken currentDraft newdCID sCID dCID
                  newtoken <- encryptRetryToken tokenSecret retryToken
                  bin <- encodeRetry currentDraft sCID newdCID dCID newtoken
                  send bin
                else do
                  q <- newTQueueIO
                  atomicModifyIORef' routeTable $ \rt' -> (M.insert newdCID q rt', ())
                  -- fixme: check listen length
                  atomically $ writeTQueue q bs
                  atomically $ writeTQueue acceptQueue $ Accept newdCID sCID dCID mysa peersa q
          Just q -> atomically $ writeTQueue q bs -- resend packets
  | otherwise = do
        mretryToken <- decryptRetryToken tokenSecret token
        case mretryToken of
          Nothing -> return ()
          Just RetryToken{..} -> do
              when (tokenVersion /= ver) $ error "dispatch: fixme"
              when (dCID /= localCID) $ error "dispatch: fixme"
              when (sCID /= remoteCID) $ error "dispatch: fixme"
              q <- newTQueueIO
              atomicModifyIORef' routeTable $ \rt' -> (M.insert dCID q rt', ())
              -- fixme: check listen length
              atomically $ writeTQueue q bs
              -- fixme: origLocalCID
              atomically $ writeTQueue acceptQueue $ Accept dCID sCID origLocalCID mysa peersa q
dispatch _ ServerRoute{..} (PHShort dCID) _ _ _ _ = do
    rt <- readIORef routeTable
    let mroute = M.lookup dCID rt
    case mroute of
      Nothing -> pathValidation
      Just _  -> return () -- connected socket is done? No. fixme.
dispatch _ _ _ _ _ _ _ = return ()

----------------------------------------------------------------

encodeVersionNegotiation :: CID -> CID -> [Version] -> IO ByteString
encodeVersionNegotiation dCID sCID vers = withWriteBuffer 2048 $ \wbuf -> do
    -- flag
    -- fixme: randomizing unused bits
    write8 wbuf 0b10000000
    -- ver .. sCID
    encodeLongHeader wbuf Negotiation dCID sCID
    -- vers
    mapM_ (write32 wbuf . encodeVersion) vers

encodeRetry :: Version -> CID -> CID -> CID -> ByteString -> IO ByteString
encodeRetry ver dCID sCID odCID token = withWriteBuffer 2048 $ \wbuf -> do
    let flags = encodeLongHeaderPacketType 0b00000000 LHRetry
    write8 wbuf flags
    encodeLongHeader wbuf ver dCID sCID
    let (odcid, odcidlen) = unpackCID odCID
    write8 wbuf odcidlen
    copyShortByteString wbuf odcid
    copyByteString wbuf token
