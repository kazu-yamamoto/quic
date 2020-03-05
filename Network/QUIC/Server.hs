{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

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
import Data.Hourglass (Seconds(..), timeDiff, ElapsedP)
import Data.IORef
import Data.Map (Map)
import qualified Data.Map as M
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ
import qualified GHC.IO.Exception as E
import Network.ByteOrder
import Network.Socket hiding (accept)
import qualified Network.Socket.ByteString as NSB
import qualified System.IO.Error as E
import Time.System (timeCurrent, timeCurrentP)
import System.Timeout

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Qlog
import Network.QUIC.Socket
import Network.QUIC.TLS
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

data Entry = Entry Connection (IORef (Maybe MigrationQ))

-- Destination CID -> Entry
newtype ConnectionDict = ConnectionDict (Map CID Entry)

emptyConnectionDict :: ConnectionDict
emptyConnectionDict = ConnectionDict M.empty

lookupConnectionDict :: IORef ConnectionDict -> CID -> IO (Maybe Entry)
lookupConnectionDict ref cid = do
    ConnectionDict tbl <- readIORef ref
    return $ M.lookup cid tbl

registerConnectionDict :: IORef ConnectionDict -> CID -> Connection -> IO ()
registerConnectionDict ref cid conn = do
    mq <- newIORef Nothing :: IO (IORef (Maybe MigrationQ))
    let ent = Entry conn mq
    atomicModifyIORef' ref $ \(ConnectionDict tbl) ->
        (ConnectionDict $ M.insert cid ent tbl, ())

unregisterConnectionDict :: IORef ConnectionDict -> CID -> IO ()
unregisterConnectionDict ref cid = atomicModifyIORef' ref $ \(ConnectionDict tbl) ->
  (ConnectionDict $ M.delete cid tbl, ())

----------------------------------------------------------------

-- Original destination CID -> RecvQ
newtype RecvQDict = RecvQDict (OrdPSQ CID ElapsedP RecvQ)

recvQDictSize :: Int
recvQDictSize = 100

emptyRecvQDict :: RecvQDict
emptyRecvQDict = RecvQDict PSQ.empty

lookupRecvQDict :: IORef RecvQDict -> CID -> IO (Maybe RecvQ)
lookupRecvQDict ref dcid = do
    RecvQDict qt <- readIORef ref
    return $ case PSQ.lookup dcid qt of
      Nothing     -> Nothing
      Just (_,q)  -> Just q

insertRecvQDict :: IORef RecvQDict -> CID -> RecvQ -> IO ()
insertRecvQDict ref dcid q = do
    RecvQDict qt0 <- readIORef ref
    let qt1 | PSQ.size qt0 <= recvQDictSize = qt0
            | otherwise = PSQ.deleteMin qt0
    p <- timeCurrentP
    let qt2 = PSQ.insert dcid p q qt1
    writeIORef ref $ RecvQDict qt2

----------------------------------------------------------------

data Accept = Accept Version CID CID OrigCID SockAddr SockAddr RecvQ (CID -> Connection -> IO ()) (CID -> IO ()) Bool -- retried

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

newtype MigrationQ = MigrationQ (TQueue CryptPacket)

newMigrationQ :: IO MigrationQ
newMigrationQ = MigrationQ <$> newTQueueIO

readMigrationQ :: MigrationQ -> IO CryptPacket
readMigrationQ (MigrationQ q) = atomically $ readTQueue q

writeMigrationQ :: MigrationQ -> CryptPacket -> IO ()
writeMigrationQ (MigrationQ q) x = atomically $ writeTQueue q x

----------------------------------------------------------------

runDispatcher :: Dispatch -> ServerConfig -> (Socket, SockAddr) -> IO ThreadId
runDispatcher d conf ssa@(s,_) =
    forkFinally (dispatcher d conf ssa) (\_ -> close s)

dispatcher :: Dispatch -> ServerConfig -> (Socket, SockAddr) -> IO ()
dispatcher d conf (s,mysa) = handleLog logAction $ do
    let (opt,_cmsgid) = case mysa of
          SockAddrInet{}  -> (RecvIPv4PktInfo, CmsgIdIPv4PktInfo)
          SockAddrInet6{} -> (RecvIPv6PktInfo, CmsgIdIPv6PktInfo)
          _               -> error "dispatcher"
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
        let send bs = void $ NSB.sendMsg s peersa [bs] cmsgs' 0
        dispatch d conf pkt mysa peersa send bs0RTT
  where
    logAction msg = putStrLn ("dispatcher: " ++ msg)
    recv = do
        ex <- E.try $ NSB.recvMsg s 2048 64 0
        case ex of
           Right x -> return x
           Left se
             | Just E.ThreadKilled <- E.fromException se -> E.throwIO se
             | otherwise -> case E.fromException se of
                  Just e | E.ioeGetErrorType e == E.InvalidArgument -> E.throwIO se
                  _ -> do
                      print se
                      putStrLn "recv again"
                      recv

----------------------------------------------------------------

-- If client initial is fragmented into multiple packets,
-- there is no way to put the all packets into a single queue.
-- Rather, each fragment packet is put into its own queue.
-- For the first fragment, handshake would successif others are
-- retransmitted.
-- For the other fragments, handshake will fail since its socket
-- cannot be connected.
dispatch :: Dispatch -> ServerConfig -> PacketI -> SockAddr -> SockAddr -> (ByteString -> IO ()) -> ByteString -> IO ()
dispatch Dispatch{..} ServerConfig{..}
         (PacketIC cpkt@(CryptPacket (Initial ver dCID sCID token) _))
         mysa peersa send bs0RTT
  | ver `notElem` confVersions scConfig = do
        bss <- encodeVersionNegotiationPacket $ VersionNegotiationPacket sCID dCID (confVersions scConfig)
        send bss
  | token == "" = do
        mq <- lookupConnectionDict dstTable dCID
        case mq of
          Nothing
            | scRequireRetry -> sendRetry
            | otherwise      -> pushToAcceptFirst
          _                  -> putStrLn "dispatch: Just (1)"
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
                    _       -> putStrLn "dispatch: Just (2)"
          _ -> sendRetry
  where
    pushToAcceptQ d s o wrap retried = do
        mq <- lookupRecvQDict srcTable o
        case mq of
          Just q -> writeRecvQ q cpkt
          Nothing -> do
              q <- newRecvQ
              insertRecvQDict srcTable o q
              writeRecvQ q cpkt
              let oc = wrap o
                  reg = registerConnectionDict dstTable
                  unreg = unregisterConnectionDict dstTable
                  ent = Accept ver d s oc mysa peersa q reg unreg retried
              -- fixme: check acceptQ length
              writeAcceptQ acceptQ ent
              when (bs0RTT /= "") $ do
                  (PacketIC cpktRTT0, _) <- decodePacket bs0RTT
                  writeRecvQ q cpktRTT0
    pushToAcceptFirst = do
        newdCID <- newCID
        pushToAcceptQ newdCID sCID dCID OCFirst False
    pushToAcceptRetried (CryptoToken _ _ (Just (_,_,o))) =
        pushToAcceptQ dCID sCID  o OCRetry True
    pushToAcceptRetried _ = return ()
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
dispatch Dispatch{..} _ (PacketIC cpkt@(CryptPacket hdr@(Short dCID) crypt)) _ peersa _ _ = do
    -- fixme: packets for closed connections also match here.
    mx <- lookupConnectionDict dstTable dCID
    case mx of
      Nothing -> do
          putStrLn $ "CID no match: " ++ show dCID ++ ", " ++ show peersa
      Just (Entry conn ref)  -> do
          mplain <- decryptCrypt conn crypt RTT1Level
          case mplain of
            Nothing -> connDebugLog conn $ "Cannot decrypt in dispatch"
            Just plain -> do
                mmq <- readIORef ref
                case mmq of
                  Just mq -> writeMigrationQ mq cpkt
                  Nothing -> do
                      qlogReceived conn $ PlainPacket hdr plain
                      let cpkt' = CryptPacket hdr crypt { cryptLogged = True }
                      migration conn peersa dCID ref cpkt'
dispatch _ _ (PacketIB _)  _ _ _ _ = print BrokenPacket
dispatch _ _ _ _ _ _ _ = return () -- throwing away

----------------------------------------------------------------

-- | readerServer dies when the socket is closed.
readerServer :: Socket -> RecvQ -> LogAction -> IO ()
readerServer s q logAction = handleLog logAction' $ forever $ do
    pkts <- NSB.recv s 2048 >>= decodeCryptPackets
    mapM (writeRecvQ q) pkts
  where
    logAction' msg = logAction $ "readerServer: " ++ msg

recvServer :: RecvQ -> IO CryptPacket
recvServer q = readRecvQ q

----------------------------------------------------------------

migration :: Connection -> SockAddr -> CID -> IORef (Maybe MigrationQ) -> CryptPacket -> IO ()
migration conn peersa dCID ref cpkt = do
    mRetiredSeqNum <- choosePeerCID conn
    case mRetiredSeqNum of
      Nothing -> connDebugLog conn "No new peer CID"
      Just retiredSeqNum -> do
          connDebugLog conn $ "Migrating to " ++ show peersa
          mq <- newMigrationQ
          writeIORef ref $ Just mq
          void $ forkIO $ migrator conn peersa mq dCID retiredSeqNum
          writeMigrationQ mq cpkt

migrator :: Connection -> SockAddr -> MigrationQ -> CID -> Int -> IO ()
migrator conn peersa1 mq dcid retiredSeqNum = do
    (s0,q) <- readIORef $ sockInfo conn
    mysa <- getSocketName s0
    s1 <- udpServerConnectedSocket mysa peersa1
    writeIORef (sockInfo conn) (s1,q)
    void $ forkIO $ readerServer s1 q $ connDebugLog conn
    _ <- setMyCID conn dcid -- fixme: sending error if False
    pdat <- newPathData
    setChallenges conn [pdat]
    putOutput conn $ OutControl RTT1Level [PathChallenge pdat, RetireConnectionID retiredSeqNum]
    waitResponse conn
    _ <- timeout 2000000 $ forever (readMigrationQ mq >>= writeRecvQ q)
    retirePeerCID conn retiredSeqNum
    close s0
