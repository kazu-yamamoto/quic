{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Core where

import Control.Concurrent
import qualified Control.Exception as E
import Data.IORef
import qualified Network.Socket as NS
import qualified Network.Socket.ByteString as NSB
import qualified Network.TLS as TLS
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

-- | Data type to represent a QUIC client.
newtype QUICClient = QUICClient {
    clientConfig :: ClientConfig
  }

-- | Data type to represent a QUIC server.
data QUICServer = QUICServer {
    serverConfig :: ServerConfig
  , serverRoute  :: ServerRoute
  }

----------------------------------------------------------------

-- | Creating 'QUICClient' and running an IO action.
withQUICClient :: ClientConfig -> (QUICClient -> IO a) -> IO a
withQUICClient conf body = do
    when (null $ confVersions $ ccConfig conf) $ E.throwIO NoVersionIsSpecified
    let qc = QUICClient conf
    body qc

-- | Connecting the server specified in 'ClientConfig' and returning a 'Connection'.
connect :: QUICClient -> IO Connection
connect QUICClient{..} = do
    let firstVersion = head $ confVersions $ ccConfig clientConfig
    ex0 <- E.try $ connect' firstVersion
    case ex0 of
      Right conn0 -> return conn0
      Left se0 -> case check se0 of
        Left  se0' -> E.throwIO se0'
        Right ver -> do
            ex1 <- E.try $ connect' ver
            case ex1 of
              Right conn1 -> return conn1
              Left se1 -> case check se1 of
                Left  se1' -> E.throwIO se1'
                Right _    -> E.throwIO VersionNegotiationFailed
  where
    connect' ver = do
        (conn,cls) <- createClientConnection clientConfig ver
        handshakeClientConnection clientConfig conn `E.onException` cls
        return conn
    check se
      | Just e@(TLS.Error_Protocol _) <- E.fromException se =
                Left $ HandshakeFailed $ show $ errorToAlertDescription e
      | Just (NextVersion ver) <- E.fromException se = Right ver
      | Just (e :: QUICError)  <- E.fromException se = Left e
      | otherwise = Left $ BadThingHappen se

createClientConnection :: ClientConfig -> Version -> IO (Connection, IO ())
createClientConnection conf@ClientConfig{..} ver = do
    s0 <- udpClientConnectedSocket ccServerName ccPortName
    sref <- newIORef s0
    q <- newClientRecvQ
    let cls = do
            s <- readIORef sref
            NS.close s
        send bss = do
            s <- readIORef sref
            void $ NSB.sendMany s bss
        recv = recvClient q
    myCID   <- newCID
    peerCID <- newCID
    conn <- clientConnection conf ver myCID peerCID send recv cls
    -- killed by "close s0"
    void $ forkIO $ readerClient conf s0 q conn
    return (conn,cls)

handshakeClientConnection :: ClientConfig -> Connection -> IO ()
handshakeClientConnection conf@ClientConfig{..} conn = do
    setToken conn $ resumptionToken ccResumption
    setCryptoOffset conn InitialLevel 0
    setCryptoOffset conn HandshakeLevel 0
    setCryptoOffset conn RTT1Level 0
    setStreamOffset conn 0 0 -- fixme
    tid0 <- forkIO $ sender   conn
    tid1 <- forkIO $ receiver conn
    tid2 <- forkIO $ resender conn
    setThreadIds conn [tid0,tid1,tid2]
    handshakeClient conf conn `E.onException` clearThreads conn
    setConnectionOpen conn

----------------------------------------------------------------

-- | Creating 'QUICServer' and running an IO action.
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

-- | Accepting a connection from a client and returning a 'Connection'.
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
            tid0 <- forkIO $ sender   conn
            tid1 <- forkIO $ receiver conn
            tid2 <- forkIO $ resender conn
            setThreadIds conn [tid0,tid1,tid2]
            handshakeServer serverConfig oCID conn `E.onException` clearThreads conn
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
