{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Route.Server (
    ServerConfig(..)
  , defaultServerConfig
  , QUICServer(..)
  , withQUICServer
  , Accept(..)
  ) where

import Control.Concurrent
import Control.Concurrent.STM
import Data.IORef
import Data.IP
import Data.Map (Map)
import qualified Data.Map as M
import Network.ByteOrder
import Network.QUIC.Socket
import Network.Socket
import qualified Network.Socket.ByteString as NBS

import Network.QUIC.Config
import Network.QUIC.Imports
import Network.QUIC.Route.Header
import Network.QUIC.Route.Token
import Network.QUIC.TLS
import Network.QUIC.Transport

-- fixme: oCID to TLS
data Accept = Accept CID CID CID SockAddr SockAddr (TQueue ByteString)

data QUICServer = QUICServer {
    serverConfig :: ServerConfig
  , tokenSecret  :: TokenSecret
  , routeTable   :: IORef RouteTable
  , acceptQueue  :: TQueue Accept
  }

type RouteTable = Map CID (TQueue ByteString)

withQUICServer :: ServerConfig -> (QUICServer -> IO ()) -> IO ()
withQUICServer sc body = do
    ts <- generateTokenSecret
    rt <- newIORef M.empty
    aq <- newTQueueIO
    let conf = QUICServer sc ts rt aq
    mapM_ (void . forkIO . runRouter conf) $ scAddresses sc
    body conf

runRouter :: QUICServer -> (IP, PortNumber) -> IO ()
runRouter quicServer ip = do
    (s,mysa) <- udpServerListenSocket ip
    let recv = NBS.recvFrom s 2048
    forever $ do
        (bs,peersa) <- recv
        ph <- decodePlainHeader bs
        let send bin = void $ NBS.sendTo s bin peersa
        router quicServer ph mysa peersa bs send

pathValidation :: IO ()
pathValidation = undefined

supportedVersions :: [Version]
supportedVersions = [Draft24, Draft23]

----------------------------------------------------------------

-- fixme: deleting unnecessary Entry
router :: QUICServer -> PlainHeader -> SockAddr -> SockAddr -> ByteString -> (ByteString -> IO ()) -> IO ()
router QUICServer{..} (PHInitial ver dCID sCID token) mysa peersa bs send
  | ver /= currentDraft && ver `elem` supportedVersions = do
        bin <- encodeVersionNegotiation sCID dCID (delete ver supportedVersions)
        send bin
  | token == "" = do
        rt <- readIORef routeTable
        let mroute = M.lookup dCID rt
        case mroute of
          Nothing -> do
              newdCID <- newCID
              if scRequireRetry serverConfig then do
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
              when (tokenVersion /= ver) $ error "router: fixme"
              when (dCID /= localCID) $ error "router: fixme"
              when (sCID /= remoteCID) $ error "router: fixme"
              -- fixme: telling oCID for parameters in Crypto.
              -- fixme: creating new TQueue
              q <- newTQueueIO
              atomicModifyIORef' routeTable $ \rt' -> (M.insert dCID q rt', ())
              -- fixme: check listen length
              atomically $ writeTQueue q bs
              -- fixme: specifying dCID is correct?
              atomically $ writeTQueue acceptQueue $ Accept dCID sCID dCID mysa peersa q
router QUICServer{..} (PHShort dCID) _ _ _ _ = do
    rt <- readIORef routeTable
    let mroute = M.lookup dCID rt
    case mroute of
      Nothing -> pathValidation
      Just _  -> return () -- connected socket is done? No. fixme.
router _ _ _ _ _ _ = return ()

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
