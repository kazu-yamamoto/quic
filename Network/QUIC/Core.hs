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

import Network.QUIC.Client
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Handshake
import Network.QUIC.Imports
import Network.QUIC.Receiver
import Network.QUIC.Sender
import Network.QUIC.Server
import Network.QUIC.Socket
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
    s0 <- udpClientConnectedSocket (ccServerName clientConfig) (ccPortName clientConfig)
    sref <- newIORef s0
    connref <- newIORef Nothing
    q <- newClientRecvQ
    void $ forkIO $ readerClient clientConfig s0 q connref -- killed by "close s0"
    let cls = do
            s <- readIORef sref
            NS.close s
        send bss = do
            s <- readIORef sref
            void $ NSB.sendMany s bss
        recv = recvClient q
    let setup = do
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
    setup `E.onException` cls
  where
    tlserr e = E.throwIO $ HandshakeFailed $ show $ errorToAlertDescription e

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

accept :: QUICServer -> IO Connection
accept QUICServer{..} = E.handle tlserr $ do
    Accept ver myCID peerCID oCID mysa peersa0 q register unregister retried
      <- readAcceptQ $ acceptQueue serverRoute
    s0 <- udpServerConnectedSocket mysa peersa0
    sref <- newIORef (s0,peersa0)
    void $ forkIO $ readerServer s0 q -- killed by "close s0"
    let cls = do
            (s,_) <- readIORef sref
            NS.close s
        send bss = void $ do
            (s,_) <- readIORef sref
            NSB.sendMany s bss
        recv = recvServer mysa q sref
        setup = do
            conn <- serverConnection serverConfig ver myCID peerCID oCID send recv cls
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

----------------------------------------------------------------

reportError :: E.SomeException -> IO ()
reportError e
  | Just E.ThreadKilled <- E.fromException e = return ()
  | otherwise                                = print e
