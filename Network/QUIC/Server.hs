{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Server (
    Dispatch
  , newDispatch
  , clearDispatch
  , runDispatcher
  , tokenMgr
  -- * Accepting
  , accept
  , Accept(..)
  -- * Receiving and reading
  , RecvQ
  , recvServer
  , readerServer
  ) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Crypto.Token as CT
import qualified Data.ByteString as BS
import Data.Map (Map)
import qualified Data.Map as M
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ
import qualified GHC.IO.Exception as E
import Network.ByteOrder
import Network.Socket hiding (accept)
import qualified Network.Socket.ByteString as NSB
import qualified System.IO.Error as E

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Socket
import Network.QUIC.TLS
import Network.QUIC.Timeout
import Network.QUIC.Types

----------------------------------------------------------------

data Dispatch = Dispatch {
    tokenMgr :: CT.TokenManager
  , dstTable :: IORef ConnectionDict
  , srcTable :: IORef RecvQDict
  , acceptQ  :: AcceptQ
  }

newDispatch :: IO Dispatch
newDispatch = Dispatch <$> CT.spawnTokenManager CT.defaultConfig
                       <*> newIORef emptyConnectionDict
                       <*> newIORef emptyRecvQDict
                       <*> newAcceptQ

clearDispatch :: Dispatch -> IO ()
clearDispatch d = CT.killTokenManager $ tokenMgr d

----------------------------------------------------------------

newtype ConnectionDict = ConnectionDict (Map CID Connection)

emptyConnectionDict :: ConnectionDict
emptyConnectionDict = ConnectionDict M.empty

lookupConnectionDict :: IORef ConnectionDict -> CID -> IO (Maybe Connection)
lookupConnectionDict ref cid = do
    ConnectionDict tbl <- readIORef ref
    return $ M.lookup cid tbl

registerConnectionDict :: IORef ConnectionDict -> CID -> Connection -> IO ()
registerConnectionDict ref cid conn = atomicModifyIORef'' ref $
    \(ConnectionDict tbl) -> ConnectionDict $ M.insert cid conn tbl

unregisterConnectionDict :: IORef ConnectionDict -> CID -> IO ()
unregisterConnectionDict ref cid = atomicModifyIORef'' ref $
    \(ConnectionDict tbl) -> ConnectionDict $ M.delete cid tbl

----------------------------------------------------------------

-- Original destination CID -> RecvQ
data RecvQDict = RecvQDict Int (OrdPSQ CID Int RecvQ)

recvQDictSize :: Int
recvQDictSize = 100

emptyRecvQDict :: RecvQDict
emptyRecvQDict = RecvQDict 0 PSQ.empty

lookupRecvQDict :: IORef RecvQDict -> CID -> IO (Maybe RecvQ)
lookupRecvQDict ref dcid = do
    RecvQDict _ qt <- readIORef ref
    return $ case PSQ.lookup dcid qt of
      Nothing     -> Nothing
      Just (_,q)  -> Just q

insertRecvQDict :: IORef RecvQDict -> CID -> RecvQ -> IO ()
insertRecvQDict ref dcid q = atomicModifyIORef'' ref ins
  where
    ins (RecvQDict p qt0) = let qt1 | PSQ.size qt0 <= recvQDictSize = qt0
                                    | otherwise = PSQ.deleteMin qt0
                                qt2 = PSQ.insert dcid p q qt1
                                p' = p + 1 -- fixme: overflow
                            in RecvQDict p' qt2

----------------------------------------------------------------

data Accept = Accept Version AuthCIDs AuthCIDs SockAddr SockAddr RecvQ Int (CID -> Connection -> IO ()) (CID -> IO ())

newtype AcceptQ = AcceptQ (TQueue Accept)

newAcceptQ :: IO AcceptQ
newAcceptQ = AcceptQ <$> newTQueueIO

readAcceptQ :: AcceptQ -> IO Accept
readAcceptQ (AcceptQ q) = atomically $ readTQueue q

writeAcceptQ :: AcceptQ -> Accept -> IO ()
writeAcceptQ (AcceptQ q) x = atomically $ writeTQueue q x

accept :: Dispatch -> IO Accept
accept = readAcceptQ . acceptQ

----------------------------------------------------------------

runDispatcher :: Dispatch -> ServerConfig -> (Socket, SockAddr) -> IO ThreadId
runDispatcher d conf ssa@(s,_) =
    forkFinally (dispatcher d conf ssa) (\_ -> close s)

dispatcher :: Dispatch -> ServerConfig -> (Socket, SockAddr) -> IO ()
dispatcher d conf (s,mysa) = handleLog logAction $ do
--    let (opt,_cmsgid) = case mysa of
--          SockAddrInet{}  -> (RecvIPv4PktInfo, CmsgIdIPv4PktInfo)
--          SockAddrInet6{} -> (RecvIPv6PktInfo, CmsgIdIPv6PktInfo)
--          _               -> error "dispatcher"
--    setSocketOption s opt 1
    forever $ do
--        (peersa, bs0, _cmsgs, _) <- recv
        (bs0, peersa) <- recv
        -- macOS overrides the local address of the socket
        -- if in_pktinfo is used.
-- #if defined(darwin_HOST_OS)
--         let cmsgs' = []
-- #else
--         let cmsgs' = filterCmsg _cmsgid _cmsgs
-- #endif
        (pkt, bs0RTT) <- decodePacket bs0
--        let send bs = void $ NSB.sendMsg s peersa [bs] cmsgs' 0
        let send bs = void $ NSB.sendTo s bs peersa
            pktSiz = BS.length bs0 -- both Initial and 0RTT
        dispatch d conf pkt mysa peersa send bs0RTT pktSiz
  where
    logAction msg = stdoutLogger ("dispatcher: " <> msg)
    recv = do
--        ex <- E.try $ NSB.recvMsg s maximumUdpPayloadSize 64 0
        ex <- E.try $ NSB.recvFrom s maximumUdpPayloadSize
        case ex of
           Right x -> return x
           Left se
             | Just E.ThreadKilled <- E.fromException se -> E.throwIO se
             | otherwise -> case E.fromException se of
                  Just e | E.ioeGetErrorType e == E.InvalidArgument -> E.throwIO se
                  _ -> do
                      stdoutLogger $ "recv again: " <> bhow se
                      recv

----------------------------------------------------------------

-- If client initial is fragmented into multiple packets,
-- there is no way to put the all packets into a single queue.
-- Rather, each fragment packet is put into its own queue.
-- For the first fragment, handshake would successif others are
-- retransmitted.
-- For the other fragments, handshake will fail since its socket
-- cannot be connected.
dispatch :: Dispatch -> ServerConfig -> PacketI -> SockAddr -> SockAddr -> (ByteString -> IO ()) -> ByteString -> Int -> IO ()
dispatch Dispatch{..} ServerConfig{..}
         (PacketIC cpkt@(CryptPacket (Initial ver dCID sCID token) _))
         mysa peersa send bs0RTT pktSiz
  | pktSiz < defaultQUICPacketSize = do
        stdoutLogger $ "dispatch: too small " <> bhow pktSiz <> ", " <> bhow peersa
  | ver `notElem` confVersions scConfig = do
        let vers | ver == GreasingVersion = GreasingVersion2 : confVersions scConfig
                 | otherwise = GreasingVersion : confVersions scConfig
        bss <- encodeVersionNegotiationPacket $ VersionNegotiationPacket sCID dCID vers
        send bss
  | token == "" = do
        mq <- lookupConnectionDict dstTable dCID
        case mq of
          Nothing
            | scRequireRetry -> sendRetry
            | otherwise      -> pushToAcceptFirst
          _                  -> stdoutLogger $ "dispatch: Just (1) " <> bhow peersa
  | otherwise = do
        mct <- decryptToken tokenMgr token
        case mct of
          Just ct
            | isRetryToken ct -> do
                  ok <- isRetryTokenValid ct
                  if ok then pushToAcceptRetried ct else sendRetry
            | otherwise -> do
                  mq <- lookupConnectionDict dstTable dCID
                  case mq of
                    Nothing -> pushToAcceptFirst
                    _       -> stdoutLogger $ "dispatch: Just (2) " <> bhow peersa
          _ -> sendRetry
  where
    pushToAcceptQ myAuthCIDs peerAuthCIDs key = do
        mq <- lookupRecvQDict srcTable key
        case mq of
          Just q -> writeRecvQ q cpkt
          Nothing -> do
              q <- newRecvQ
              insertRecvQDict srcTable key q
              writeRecvQ q cpkt
              let reg = registerConnectionDict dstTable
                  unreg = unregisterConnectionDict dstTable
                  ent = Accept ver myAuthCIDs peerAuthCIDs mysa peersa q pktSiz reg unreg
              -- fixme: check acceptQ length
              writeAcceptQ acceptQ ent
              when (bs0RTT /= "") $ do
                  (PacketIC cpktRTT0, _) <- decodePacket bs0RTT
                  writeRecvQ q cpktRTT0
    -- Initial: DCID=S1, SCID=C1 ->
    --                                     <- Initial: DCID=C1, SCID=S2
    --                               ...
    -- 1-RTT: DCID=S2 ->
    --                                                <- 1-RTT: DCID=C1
    --
    -- initial_source_connection_id       = S2   (newdCID)
    -- original_destination_connection_id = S1   (dCID)
    -- retry_source_connection_id         = Nothing
    pushToAcceptFirst = do
        newdCID <- newCID
        let myAuthCIDs = defaultAuthCIDs {
                initSrcCID  = Just newdCID
              , origDstCID  = Just dCID
              }
            peerAuthCIDs = defaultAuthCIDs {
                initSrcCID = Just sCID
              }
        pushToAcceptQ myAuthCIDs peerAuthCIDs dCID
    -- Initial: DCID=S1, SCID=C1 ->
    --                                       <- Retry: DCID=C1, SCID=S2
    -- Initial: DCID=S2, SCID=C1 ->
    --                                     <- Initial: DCID=C1, SCID=S3
    --                               ...
    -- 1-RTT: DCID=S3 ->
    --                                                <- 1-RTT: DCID=C1
    --
    -- initial_source_connection_id       = S3   (dCID)  S2 in our server
    -- original_destination_connection_id = S1   (o)
    -- retry_source_connection_id         = S2   (dCID)
    pushToAcceptRetried (CryptoToken _ _ (Just (_,_,o))) = do
        let myAuthCIDs = defaultAuthCIDs {
                initSrcCID  = Just dCID
              , origDstCID  = Just o
              , retrySrcCID = Just dCID
              }
            peerAuthCIDs = defaultAuthCIDs {
                initSrcCID = Just sCID
              }
        pushToAcceptQ myAuthCIDs peerAuthCIDs o
    pushToAcceptRetried _ = return ()
    isRetryTokenValid (CryptoToken tver tim (Just (l,r,_))) = do
        diff <- getElapsedTimeMicrosecond tim
        return $ tver == ver
              && diff <= Microseconds 30000000 -- fixme
              && dCID == l
              && sCID == r
    isRetryTokenValid _ = return False
    sendRetry = do
        newdCID <- newCID
        retryToken <- generateRetryToken ver newdCID sCID dCID
        newtoken <- encryptToken tokenMgr retryToken
        bss <- encodeRetryPacket $ RetryPacket ver sCID newdCID newtoken (Left dCID)
        send bss
dispatch Dispatch{..} _ (PacketIC cpkt@(CryptPacket (RTT0 _ o _) _)) _ peersa _ _ _ = do
    mq <- lookupRecvQDict srcTable o
    case mq of
      Just q  -> writeRecvQ q cpkt
      Nothing -> stdoutLogger $ "dispatch: orphan 0RTT: " <> bhow peersa
dispatch Dispatch{..} _ (PacketIC (CryptPacket hdr@(Short dCID) crypt)) _ peersa _ _ _ = do
    -- fixme: packets for closed connections also match here.
    mx <- lookupConnectionDict dstTable dCID
    case mx of
      Nothing -> do
          stdoutLogger $ "dispatch: CID no match: " <> bhow dCID <> ", " <> bhow peersa
      Just conn -> do
          mplain <- decryptCrypt conn crypt RTT1Level
          case mplain of
            Nothing -> connDebugLog conn "dispatch: cannot decrypt"
            Just plain -> do
                qlogReceived conn $ PlainPacket hdr plain
                let cpkt' = CryptPacket hdr $ setCryptLogged crypt
                writeMigrationQ conn cpkt'
                migrating <- isPathValidating conn
                unless migrating $ do
                    setMigrationStarted conn
                    -- fixme: should not block in this loop
                    mcidinfo <- timeout (Microseconds 100000) $ choosePeerCID conn
                    connDebugLog conn $ "Migrating to " <> bhow peersa <> " (" <> bhow dCID <> ")"
                    void $ forkIO $ migrator conn peersa dCID mcidinfo

dispatch _ _ ipkt _ peersa _ _ _ = stdoutLogger $ "dispatch: orphan " <> bhow peersa <> ", " <> bhow ipkt

----------------------------------------------------------------

-- | readerServer dies when the socket is closed.
readerServer :: Socket -> RecvQ -> Connection -> IO ()
readerServer s q conn = handleLog logAction $ forever $ do
    bs <- NSB.recv s maximumUdpPayloadSize
    addRxBytes conn $ BS.length bs
    pkts <- decodeCryptPackets bs
    mapM (writeRecvQ q) pkts
  where
    logAction msg = connDebugLog conn ("readerServer: " <> msg)

recvServer :: RecvQ -> IO CryptPacket
recvServer q = readRecvQ q

----------------------------------------------------------------

migrator :: Connection -> SockAddr -> CID -> Maybe CIDInfo -> IO ()
migrator conn peersa1 dcid mcidinfo = do
    (s0,q) <- getSockInfo conn
    mysa <- getSocketName s0
    s1 <- udpServerConnectedSocket mysa peersa1
    setSockInfo conn (s1,q)
    void $ forkIO $ readerServer s1 q conn
    -- fixme: if cannot set
    setMyCID conn dcid
    validatePath conn mcidinfo
    _ <- timeout (Microseconds 2000000) $ forever (readMigrationQ conn >>= writeRecvQ q)
    close s0
