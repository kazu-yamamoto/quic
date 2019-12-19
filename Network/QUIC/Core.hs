{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Core where

import Control.Concurrent
import Control.Concurrent.STM
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
import Network.QUIC.Route
import Network.QUIC.Sender
import Network.QUIC.Socket
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

data QUICClient = QUICClient {
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
    connref <- newIORef Nothing
    let send bss = void $ NSB.sendMany s bss
        recv     = recvClient s connref
    myCID   <- newCID
    peerCID <- newCID
    conn <- clientConnection clientConfig myCID peerCID send recv
    setToken conn $ resumptionToken $ ccResumption clientConfig
    tid0 <- forkIO $ sender conn
    tid1 <- forkIO $ receiver conn
    tid2 <- forkIO $ resender conn
    setThreadIds conn [tid0,tid1,tid2]
    writeIORef connref $ Just conn
    mode <- handshakeClient clientConfig conn (ccEarlyData clientConfig)
    setTLSMode conn mode
    setConnectionState conn Open
    return conn
  where
    tlserr e = E.throwIO $ HandshakeFailed $ show $ errorToAlertDescription e

recvClient :: NS.Socket -> IORef (Maybe Connection) -> IO [CryptPacket]
recvClient s connref = do
    pkts <- NSB.recv s 2048 >>= decodePackets
    catMaybes <$> mapM go pkts
  where
    go (PacketIV _)   = return Nothing
    go (PacketIC pkt) = return $ Just pkt
    go (PacketIR (RetryPacket ver _dCID sCID _oCID token))  = do
        -- The packet number of first crypto frame is 0.
        -- This ensures that retry can be accepted only once.
        -- fixme: may checking
        mconn <- readIORef connref
        case mconn of
          Nothing   -> return ()
          Just conn -> do
              mr <- releaseOutput conn 0
              case mr of
                Just (Retrans (OutHndClientHello cdat mEarydata) _ _) -> do
                    setPeerCID conn sCID
                    setInitialSecrets conn $ initialSecrets ver sCID
                    setToken conn token
                    setCryptoOffset conn InitialLevel 0
                    atomically $ writeTQueue (outputQ conn) $ OutHndClientHello cdat mEarydata
                _ -> return ()
        return Nothing

----------------------------------------------------------------

withQUICServer :: ServerConfig -> (QUICServer -> IO ()) -> IO ()
withQUICServer conf body = do
    route <- newServerRoute
    ssas <- mapM  udpServerListenSocket $ scAddresses conf
    tids <- mapM (runRouter route) ssas
    let qs = QUICServer conf route
    body qs `E.finally` mapM_ killThread tids
  where
    runRouter route ssa@(s,_) = forkFinally (router conf route ssa) (\_ -> NS.close s)

accept :: QUICServer -> IO Connection
accept QUICServer{..} = E.handle tlserr $ do
    Accept myCID peerCID oCID mysa peersa q <- atomically $ readTQueue $ acceptQueue serverRoute
    s <- udpServerConnectedSocket mysa peersa
    let send bss = void $ NSB.sendMany s bss
        recv = do
            mpkt <- atomically $ tryReadTQueue q
            case mpkt of
              Nothing  -> NSB.recv s 2048 >>= decodeCryptPackets
              Just pkt -> return [pkt]
    conn <- serverConnection serverConfig myCID peerCID oCID send recv
    tid0 <- forkIO $ sender conn
    tid1 <- forkIO $ receiver conn
    tid2 <- forkIO $ resender conn
    setThreadIds conn [tid0,tid1,tid2]
    mode <- handshakeServer serverConfig oCID conn
    setTLSMode conn mode
    setConnectionState conn Open
    return conn
  where
    tlserr e = E.throwIO $ HandshakeFailed $ show $ errorToAlertDescription e

----------------------------------------------------------------

close :: Connection -> IO ()
close conn = do
    setConnectionState conn Closing
    let frames = [ConnectionCloseQUIC NoError 0 ""]
    atomically $ writeTQueue (outputQ conn) $ OutControl RTT1Level frames
    setCloseSent conn
    void $ timeout 100000 $ waitClosed conn -- fixme: timeout
    clearThreads conn
