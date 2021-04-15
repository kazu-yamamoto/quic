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
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ
import Foreign.Marshal.Alloc
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

data Accept = Accept {
    accVersion      :: Version
  , accMyAuthCIDs   :: AuthCIDs
  , accPeerAuthCIDs :: AuthCIDs
  , accMySockAddr   :: SockAddr
  , accPeerSockAddr :: SockAddr
  , accRecvQ        :: RecvQ
  , accPacketSize   :: Int
  , accRegister     :: CID -> Connection -> IO ()
  , accUnregister   :: CID -> IO ()
  , accAddressValidated :: Bool
  , accTime         :: TimeMicrosecond
  }

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
    forkFinally (dispatcher d conf ssa) $ \_ -> shutdownAndClose s

dispatcher :: Dispatch -> ServerConfig -> (Socket, SockAddr) -> IO ()
dispatcher d conf (s,mysa) = handleLogUnit logAction $
    E.bracket (mallocBytes maximumUdpPayloadSize)
              free
              body
  where
    body buf = do
    --    let (opt,_cmsgid) = case mysa of
    --          SockAddrInet{}  -> (RecvIPv4PktInfo, CmsgIdIPv4PktInfo)
    --          SockAddrInet6{} -> (RecvIPv6PktInfo, CmsgIdIPv6PktInfo)
    --          _               -> error "dispatcher"
    --    setSocketOption s opt 1
        forever $ do
    --        (peersa, bs0, _cmsgs, _) <- recv
            (bs0, peersa) <- recv
            let bytes = BS.length bs0 -- both Initial and 0RTT
            now <- getTimeMicrosecond
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
            dispatch d conf pkt mysa peersa send buf bs0RTT bytes now
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
dispatch :: Dispatch -> ServerConfig -> PacketI -> SockAddr -> SockAddr -> (ByteString -> IO ()) -> Buffer -> ByteString -> Int -> TimeMicrosecond -> IO ()
dispatch Dispatch{..} ServerConfig{..}
         (PacketIC cpkt@(CryptPacket (Initial ver dCID sCID token) _) lvl)
         mysa peersa send _ bs0RTT bytes tim
  | bytes < defaultQUICPacketSize = do
        stdoutLogger $ "dispatch: too small " <> bhow bytes <> ", " <> bhow peersa
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
            | otherwise      -> pushToAcceptFirst False
          _                  -> return ()
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
                    Nothing -> pushToAcceptFirst True
                    _       -> return ()
          _ -> sendRetry
  where
    pushToAcceptQ myAuthCIDs peerAuthCIDs key addrValid = do
        mq <- lookupRecvQDict srcTable key
        case mq of
          Just q -> writeRecvQ q $ mkReceivedPacket cpkt tim bytes lvl
          Nothing -> do
              q <- newRecvQ
              insertRecvQDict srcTable key q
              writeRecvQ q $ mkReceivedPacket cpkt tim bytes lvl
              let reg = registerConnectionDict dstTable
                  unreg = \cid -> do
                      fire (Microseconds 300000) $ unregisterConnectionDict dstTable cid
                  ent = Accept {
                      accVersion      = ver
                    , accMyAuthCIDs   = myAuthCIDs
                    , accPeerAuthCIDs = peerAuthCIDs
                    , accMySockAddr   = mysa
                    , accPeerSockAddr = peersa
                    , accRecvQ        = q
                    , accPacketSize   = bytes
                    , accRegister     = reg
                    , accUnregister   = unreg
                    , accAddressValidated = addrValid
                    , accTime         = tim
                    }
              -- fixme: check acceptQ length
              writeAcceptQ acceptQ ent
              when (bs0RTT /= "") $ do
                  (PacketIC cpktRTT0 lvl', _) <- decodePacket bs0RTT
                  writeRecvQ q $ mkReceivedPacket cpktRTT0 tim bytes lvl'
    -- Initial: DCID=S1, SCID=C1 ->
    --                                     <- Initial: DCID=C1, SCID=S2
    --                               ...
    -- 1-RTT: DCID=S2 ->
    --                                                <- 1-RTT: DCID=C1
    --
    -- initial_source_connection_id       = S2   (newdCID)
    -- original_destination_connection_id = S1   (dCID)
    -- retry_source_connection_id         = Nothing
    pushToAcceptFirst addrValid = do
        newdCID <- newCID
        let myAuthCIDs = defaultAuthCIDs {
                initSrcCID  = Just newdCID
              , origDstCID  = Just dCID
              }
            peerAuthCIDs = defaultAuthCIDs {
                initSrcCID = Just sCID
              }
        pushToAcceptQ myAuthCIDs peerAuthCIDs dCID addrValid
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
        pushToAcceptQ myAuthCIDs peerAuthCIDs o True
    pushToAcceptRetried _ = return ()
    isRetryTokenValid (CryptoToken tver etim (Just (l,r,_))) = do
        diff <- getElapsedTimeMicrosecond etim
        return $ tver == ver
              && diff <= Microseconds 30000000 -- fixme
              && dCID == l
              && sCID == r
    isRetryTokenValid _ = return False
    sendRetry = do
        newdCID <- newCID
        retryToken <- generateRetryToken ver newdCID sCID dCID
        mnewtoken <- timeout (Microseconds 100000) $ encryptToken tokenMgr retryToken
        case mnewtoken of
          Nothing       -> stdoutLogger "RETRY TOKEN STACKED"
          Just newtoken -> do
              bss <- encodeRetryPacket $ RetryPacket ver sCID newdCID newtoken (Left dCID)
              send bss
dispatch Dispatch{..} _ (PacketIC cpkt@(CryptPacket (RTT0 _ o _) _) lvl) _ _peersa _ _ _ bytes tim = do
    mq <- lookupRecvQDict srcTable o
    case mq of
      Just q  -> writeRecvQ q $ mkReceivedPacket cpkt tim bytes lvl
      Nothing -> return ()
dispatch Dispatch{..} _ (PacketIC (CryptPacket hdr@(Short dCID) crypt) lvl) mysa peersa _ buf _ bytes tim  = do
    -- fixme: packets for closed connections also match here.
    mx <- lookupConnectionDict dstTable dCID
    case mx of
      Nothing -> do
          stdoutLogger $ "dispatch: CID no match: " <> bhow dCID <> ", " <> bhow peersa
      Just conn -> do
          let bufsiz = maximumUdpPayloadSize
          mplain <- decryptCrypt conn buf bufsiz crypt RTT1Level
          case mplain of
            Nothing -> connDebugLog conn "dispatch: cannot decrypt"
            Just plain -> do
                addrs <- getSockAddrs conn
                let shouldIgnore = elem (mysa,peersa) addrs
                unless shouldIgnore $ do
                    qlogReceived conn (PlainPacket hdr plain) tim
                    let cpkt' = CryptPacket hdr $ setCryptLogged crypt
                    writeMigrationQ conn $ mkReceivedPacket cpkt' tim bytes lvl
                    migrating <- isPathValidating conn
                    unless migrating $ do
                        setMigrationStarted conn
                        -- fixme: should not block in this loop
                        mcidinfo <- timeout (Microseconds 100000) $ choosePeerCID conn
                        connDebugLog conn $ "Migrating to " <> bhow peersa <> " (" <> bhow dCID <> ")"
                        void $ forkIO $ migrator conn mysa peersa dCID mcidinfo

dispatch _ _ _ipkt _ _peersa _ _ _ _ _ = return ()

----------------------------------------------------------------

-- | readerServer dies when the socket is closed.
readerServer :: Socket -> RecvQ -> Connection -> IO ()
readerServer s q conn = handleLogUnit logAction loop
  where
    loop = do
        ito <- readMinIdleTimeout conn
        mbs <- timeout ito $ NSB.recv s maximumUdpPayloadSize
        case mbs of
          Nothing -> shutdownAndClose s
          Just bs -> do
              now <- getTimeMicrosecond
              let bytes = BS.length bs
              addRxBytes conn bytes
              pkts <- decodeCryptPackets bs
              mapM_ (\(p,l) -> writeRecvQ q (mkReceivedPacket p now bytes l)) pkts
              loop
    logAction msg = stdoutLogger ("readerServer: " <> msg)

recvServer :: RecvQ -> IO ReceivedPacket
recvServer = readRecvQ

----------------------------------------------------------------

migrator :: Connection -> SockAddr -> SockAddr -> CID -> Maybe CIDInfo -> IO ()
migrator conn mysa peersa1 dcid mcidinfo = handleLogUnit logAction $ do
    (s0,q) <- getSockInfo conn
    s1 <- udpServerConnectedSocket mysa peersa1
    setSockInfo conn (s1,q)
    void $ forkIO $ readerServer s1 q conn
    -- fixme: if cannot set
    setMyCID conn dcid
    validatePath conn mcidinfo
    _ <- timeout (Microseconds 2000000) $ forever (readMigrationQ conn >>= writeRecvQ q)
    shutdownAndClose s0
  where
    logAction msg = connDebugLog conn ("migrator: " <> msg)
