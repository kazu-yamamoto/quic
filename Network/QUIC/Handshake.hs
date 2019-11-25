{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

import Control.Concurrent.STM
import qualified Control.Exception as E
import Data.ByteString hiding (putStrLn)
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Parameters
import Network.QUIC.TLS
import Network.QUIC.Transport

----------------------------------------------------------------

sendCryptoData :: Connection -> PacketType -> ByteString -> IO ()
sendCryptoData conn pt bs =
    atomically $ writeTQueue (outputQ conn) $ H pt bs emptyToken

recvCryptoData :: Connection -> IO (PacketType, ByteString)
recvCryptoData conn = do
    dat <- atomically $ readTQueue (inputQ conn)
    case dat of
      H pt bs _ -> return (pt, bs)
      E err     -> E.throwIO $ HandshakeRejectedByPeer err
      _         -> error "recvCryptoData"

----------------------------------------------------------------

handshakeClient :: ClientConfig -> Connection -> IO ()
handshakeClient conf conn = do
    control <- clientController conf
    setClientController conn control
    sendClientHelloAndRecvServerHello control conn
    recvServerFinishedSendClientFinished control conn

sendClientHelloAndRecvServerHello :: ClientController-> Connection -> IO ()
sendClientHelloAndRecvServerHello control conn = do
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

recvServerFinishedSendClientFinished :: ClientController -> Connection -> IO ()
recvServerFinishedSendClientFinished control conn = loop
  where
    loop = do
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

handshakeServer :: ServerConfig -> OrigCID -> Connection -> IO ()
handshakeServer conf origCID conn = do
    control <- serverController conf origCID
    (Initial, ch) <- recvCryptoData conn
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
    return ()

setParameters :: Connection -> [ExtensionRaw] -> IO ()
setParameters conn [ExtensionRaw 0xffa5 params] = do
    let Just plist = decodeParametersList params
    setPeerParameters conn plist
setParameters _ _ = return ()
