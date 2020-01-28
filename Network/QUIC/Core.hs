{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternGuards #-}

module Network.QUIC.Core where

import Control.Concurrent
import qualified Control.Exception as E
import Data.IORef
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB
import Network.TLS.QUIC
import System.Timeout

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Handshake
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Receiver
import Network.QUIC.Sender
import Network.QUIC.Server
import Network.QUIC.Socket
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

newtype QUICClient = QUICClient {
    clientConfig :: ClientConfig
  }

data QUICServer = QUICServer {
    serverConfig :: ServerConfig
  , serverRoute  :: ServerRoute
  }

----------------------------------------------------------------

withQUICClient :: ClientConfig -> (QUICClient -> IO a) -> IO a
withQUICClient conf body = do
    let qc = QUICClient conf
    body qc

connect :: QUICClient -> IO Connection
connect QUICClient{..} = E.handle tlserr $ do
    s <- udpClientConnectedSocket (ccServerName clientConfig) (ccPortName clientConfig)
    setup s `E.onException` NS.close s
  where
    setup s = do
        connref <- newIORef Nothing
        let send bss = void $ NSB.sendMany s bss
            recv     = recvClient s connref
            cls      = NS.close s
        myCID   <- newCID
        peerCID <- newCID
        conn <- clientConnection clientConfig myCID peerCID send recv cls
        setToken conn $ resumptionToken $ ccResumption clientConfig
        setCryptoOffset conn InitialLevel 0
        setCryptoOffset conn HandshakeLevel 0
        setCryptoOffset conn RTT1Level 0
        setStreamOffset conn 0 0 -- fixme
        tid0 <- forkIO (sender   conn `E.catch` reportError)
        tid1 <- forkIO (receiver conn `E.catch` reportError)
        tid2 <- forkIO (resender conn `E.catch` reportError)
        setThreadIds conn [tid0,tid1,tid2]
        writeIORef connref $ Just conn
        handshakeClient clientConfig conn
        setConnectionOpen conn
        return conn
    tlserr e = E.throwIO $ HandshakeFailed $ show $ errorToAlertDescription e

reportError :: E.SomeException -> IO ()
reportError e
  | Just E.ThreadKilled <- E.fromException e = return ()
  | otherwise                                = print e

recvClient :: NS.Socket -> IORef (Maybe Connection) -> IO [CryptPacket]
recvClient s connref = do
    pkts <- NSB.recv s 2048 >>= decodePackets
    catMaybes <$> mapM go pkts
  where
    go (PacketIV _)   = return Nothing
    go (PacketIC pkt) = return $ Just pkt
    go (PacketIR (RetryPacket ver dCID sCID oCID token))  = do
        -- The packet number of first crypto frame is 0.
        -- This ensures that retry can be accepted only once.
        mconn <- readIORef connref
        case mconn of
          Nothing   -> return ()
          Just conn -> do
              let localCID = myCID conn
              remoteCID <- getPeerCID conn
              when (dCID == localCID && oCID == remoteCID) $ do
                  mr <- releaseOutput conn 0
                  case mr of
                    Just (OutHndClientHello cdat mEarydata) -> do
                        setPeerCID conn sCID
                        setInitialSecrets conn $ initialSecrets ver sCID
                        setToken conn token
                        setCryptoOffset conn InitialLevel 0
                        setRetried conn True
                        putOutput conn $ OutHndClientHello cdat mEarydata
                    _ -> return ()
        return Nothing

----------------------------------------------------------------

withQUICServer :: ServerConfig -> (QUICServer -> IO ()) -> IO ()
withQUICServer conf body = do
    route <- newServerRoute
    ssas <- mapM  udpServerListenSocket $ scAddresses conf
    tids <- mapM (runRouter route) ssas
    let qs = QUICServer conf route
    body qs `E.finally` do
        killTokenManager $ tokenMgr route
        mapM_ killThread tids
  where
    runRouter route ssa@(s,_) = forkFinally (router conf route ssa) (\_ -> NS.close s)

-- reader dies when the socket is closed.
reader :: NS.Socket -> RecvQ -> IO ()
reader s q = E.handle ignore $ forever $ do
    pkts <- NSB.recv s 2048 >>= decodeCryptPackets
    mapM (\pkt -> writeRecvQ q (Through pkt)) pkts
  where
    ignore (E.SomeException _) = return ()

accept :: QUICServer -> IO Connection
accept QUICServer{..} = E.handle tlserr $ do
    Accept myCID peerCID oCID mysa peersa0 q register unregister retried
      <- readAcceptQ $ acceptQueue serverRoute
    s0 <- udpServerConnectedSocket mysa peersa0
    sref <- newIORef (s0,peersa0)
    void $ forkIO $ reader s0 q -- killed by "close s"
    let cls = do
            (s,_) <- readIORef sref
            NS.close s
        setup = do
            let send bss = void $ do
                    (s,_) <- readIORef sref
                    NSB.sendMany s bss
                recv = do
                    x <- readRecvQ q
                    case x of
                      Through pkt -> return [pkt]
                      NATRebinding pkt peersa1 -> do
                          (s,peersa) <- readIORef sref
                          when (peersa /= peersa1) $ do
                              s1 <- udpServerConnectedSocket mysa peersa1
                              writeIORef sref (s1,peersa1)
                              void $ forkIO $ reader s1 q
                              NS.close s
                          return [pkt]
            conn <- serverConnection serverConfig myCID peerCID oCID send recv cls
            setTokenManager conn $ tokenMgr serverRoute
            setCryptoOffset conn InitialLevel 0
            setCryptoOffset conn HandshakeLevel 0
            setCryptoOffset conn RTT1Level 0
            setStreamOffset conn 0 0 -- fixme
            setRetried conn retried
            tid0 <- forkIO (sender   conn `E.catch` reportError)
            tid1 <- forkIO (receiver conn `E.catch` reportError)
            tid2 <- forkIO (resender conn `E.catch` reportError)
            setThreadIds conn [tid0,tid1,tid2]
            handshakeServer serverConfig oCID conn
            setRegister conn register unregister
            register myCID
            setConnectionOpen conn
            return conn
    setup `E.onException` cls
  where
    tlserr e = E.throwIO $ HandshakeFailed $ show $ errorToAlertDescription e

----------------------------------------------------------------

close :: Connection -> IO ()
close conn = do
    unless (isClient conn) $ do
        unregister <- getUnregister conn
        unregister $ myCID conn
    let frames = [ConnectionCloseQUIC NoError 0 ""]
    putOutput conn $ OutControl RTT1Level frames
    setCloseSent conn
    void $ timeout 100000 $ waitClosed conn -- fixme: timeout
    clearThreads conn
    -- close the socket after threads reading/writing the socket die.
    connClose conn
