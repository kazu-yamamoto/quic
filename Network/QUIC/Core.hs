{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Core where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Control.Exception as E
import Network.TLS.QUIC
import System.Timeout
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB

import Network.QUIC.Handshake
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Receiver
import Network.QUIC.Route
import Network.QUIC.Sender
import Network.QUIC.Socket
import Network.QUIC.Transport

data QUICServer = QUICServer {
    serverConfig :: ServerConfig
  , serverRoute  :: ServerRoute
  }

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
    Accept mycid peercid ocid mysa peersa q <- atomically $ readTQueue $ acceptQueue serverRoute
    s <- udpServerConnectedSocket mysa peersa
    let send bs = void $ NSB.send s bs
        recv = do
            mx <- atomically $ tryReadTQueue q
            case mx of
              Nothing -> NSB.recv s 2048
              Just x  -> return x
    conn <- serverConnection serverConfig mycid peercid ocid send recv
    tid0 <- forkIO $ sender conn
    tid1 <- forkIO $ receiver conn
    setThreadIds conn [tid0,tid1]
    handshakeServer conn
    setConnectionStatus conn Open
    return conn
  where
    tlserr e = E.throwIO $ HandshakeFailed $ show $ errorToAlertDescription e

connect :: ClientConfig -> IO Connection
connect conf = E.handle tlserr $ do
    conn <- clientConnection conf
    tid0 <- forkIO $ sender conn
    tid1 <- forkIO $ receiver conn
    setThreadIds conn [tid0,tid1]
    handshakeClient conn
    setConnectionStatus conn Open
    return conn
  where
    tlserr e = E.throwIO $ HandshakeFailed $ show $ errorToAlertDescription e

close :: Connection -> IO ()
close conn = do
    setConnectionStatus conn Closing
    let frames = [ConnectionCloseQUIC NoError 0 ""]
    atomically $ writeTQueue (outputQ conn) $ C Short frames
    setCloseSent conn
    void $ timeout 100000 $ waitClosed conn -- fixme: timeout
    clearThreads conn
