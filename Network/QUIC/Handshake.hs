{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Control.Exception as E
import Data.ByteString hiding (putStrLn)
import Network.TLS.QUIC
import System.Timeout

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Receiver
import Network.QUIC.Sender
import Network.QUIC.Transport

sendCryptoData :: Connection -> PacketType -> ByteString -> IO ()
sendCryptoData conn pt bs = atomically $ writeTQueue (outputQ conn) $ H pt bs

recvCryptoData :: Connection -> IO (PacketType, ByteString)
recvCryptoData conn = do
    dat <- atomically $ readTQueue (inputQ conn)
    case dat of
      H pt bs -> return (pt, bs)
      E err   -> E.throwIO $ HandshakeRejectedByPeer err
      _       -> error "recvCryptoData"

handshake :: Config a => a -> IO Connection
handshake conf = E.handle tlserr $ do
    conn <- makeConnection conf
    tid0 <- forkIO $ sender conn
    tid1 <- forkIO $ receiver conn
    setThreadIds conn [tid0,tid1]
    if isClient conn then
        handshakeClient conn
      else
        handshakeServer conn
    setConnectionStatus conn Open
    return conn
  where
    tlserr e = E.throwIO $ HandshakeFailed $ show $ errorToAlertDescription e

bye :: Connection -> IO ()
bye conn = do
    setConnectionStatus conn Closing
    let frames = [ConnectionCloseQUIC NoError 0 ""]
    atomically $ writeTQueue (outputQ conn) $ C Short frames
    setCloseSent conn
    void $ timeout 100000 $ waitClosed conn -- fixme: timeout
    clearThreads conn

----------------------------------------------------------------

handshakeClient :: Connection -> IO ()
handshakeClient conn = do
    sendClientHelloAndRecvServerHello conn
    recvServerFinishedSendClientFinished conn

sendClientHelloAndRecvServerHello :: Connection -> IO ()
sendClientHelloAndRecvServerHello conn = do
    control <- tlsClientController conn
    SendClientHello ch0 _ <- control GetClientHello
    sendCryptoData conn Initial ch0
    (Initial, sh0) <- recvCryptoData conn
    state0 <- control $ PutServerHello sh0
    case state0 of
      RecvServerHello cipher hndSecs -> do
          setHandshakeSecrets conn hndSecs
          setCipher conn cipher
      SendClientHello ch1 _ -> do
          sendCryptoData conn Initial ch1
          (Initial, sh1) <- recvCryptoData conn
          state1 <- control $ PutServerHello sh1
          case state1 of
            RecvServerHello cipher hndSecs -> do
                setHandshakeSecrets conn hndSecs
                setCipher conn cipher
            _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"
      _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"

recvServerFinishedSendClientFinished :: Connection -> IO ()
recvServerFinishedSendClientFinished conn = loop
  where
    loop = do
        control <- tlsClientController conn
        (Handshake, eesf) <- recvCryptoData conn
        state <- control $ PutServerFinished eesf
        case state of
          ClientNeedsMore -> do
              loop
          SendClientFinished cf exts alpn appSecs -> do
              setNegotiatedProto conn alpn
              setParameters conn exts
              setApplicationSecrets conn appSecs
              sendCryptoData conn Handshake cf
          _ -> E.throwIO $ HandshakeFailed "putServerFinished"

----------------------------------------------------------------

handshakeServer :: Connection -> IO ()
handshakeServer conn = do
    (Initial, ch) <- recvCryptoData conn
    control <- tlsServerController conn
    state <- control $ PutClientHello ch
    sh <- case state of
      SendRequestRetry hrr -> do
          sendCryptoData conn Initial hrr
          (Initial, ch1) <- recvCryptoData conn
          SendServerHello sh0 exts cipher _ hndSecs <- control $ PutClientHello ch1
          setHandshakeSecrets conn hndSecs
          setCipher conn cipher
          setParameters conn exts
          return sh0
      SendServerHello sh0 exts cipher _ hndSecs -> do
          setHandshakeSecrets conn hndSecs
          setCipher conn cipher
          setParameters conn exts
          return sh0
      _ -> E.throwIO $ HandshakeFailed "handshakeServer"
    sendCryptoData conn Initial sh
    SendServerFinished sf alpn appSecs <- control GetServerFinished
    setNegotiatedProto conn alpn
    setApplicationSecrets conn appSecs
    sendCryptoData conn Handshake sf
    (Handshake, cf) <- recvCryptoData conn
    SendSessionTicket nst <- control $ PutClientFinished cf
    sendCryptoData conn Short nst
    ServerHandshakeDone <- control ExitServer
    clearController conn

setParameters :: Connection -> [ExtensionRaw] -> IO ()
setParameters conn [ExtensionRaw 0xffa5 params] = do
    let Just plist = decodeParametersList params
    setPeerParameters conn plist
setParameters _ _ = return ()
