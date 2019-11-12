module Network.QUIC.Handshake where

import Control.Concurrent
import Control.Concurrent.STM
import Data.ByteString hiding (putStrLn)
import Network.TLS.QUIC

import Network.QUIC.Context
import Network.QUIC.Receiver
import Network.QUIC.Sender
import Network.QUIC.Transport

sendCryptoData :: Context -> PacketType -> ByteString -> IO ()
sendCryptoData ctx pt bs = atomically $ writeTQueue (outputQ ctx) $ H pt bs

recvCryptoData :: Context -> IO (PacketType, ByteString)
recvCryptoData ctx = do
    H pt bs <- atomically $ readTQueue (inputQ ctx)
    return (pt, bs)

handshake :: Context -> IO ()
handshake ctx = do
    _ <- forkIO $ sender ctx
    _ <- forkIO $ receiver ctx
    if isClient ctx then
        handshakeClient ctx
      else
        handshakeServer ctx

----------------------------------------------------------------

handshakeClient :: Context -> IO ()
handshakeClient ctx = do
    sendClientHelloAndRecvServerHello ctx
    recvServerFinishedSendClientFinished ctx

sendClientHelloAndRecvServerHello :: Context -> IO ()
sendClientHelloAndRecvServerHello ctx = do
    control <- tlsClientController ctx
    SendClientHello ch0 _ <- control GetClientHello
    sendCryptoData ctx Initial ch0
    (Initial, sh0) <- recvCryptoData ctx
    state0 <- control $ PutServerHello sh0
    case state0 of
      RecvServerHello cipher hndSecs -> do
          setHandshakeSecrets ctx hndSecs
          setCipher ctx cipher
      SendClientHello ch1 _ -> do
          sendCryptoData ctx Initial ch1
          (Initial, sh1) <- recvCryptoData ctx
          state1 <- control $ PutServerHello sh1
          case state1 of
            RecvServerHello cipher hndSecs -> do
                setHandshakeSecrets ctx hndSecs
                setCipher ctx cipher
            _ -> error "sendClientHelloAndRecvServerHello"
      _ -> error "sendClientHelloAndRecvServerHello"

recvServerFinishedSendClientFinished :: Context -> IO ()
recvServerFinishedSendClientFinished ctx = loop
  where
    loop = do
        control <- tlsClientController ctx
        (Handshake, eesf) <- recvCryptoData ctx
        state <- control $ PutServerFinished eesf
        case state of
          ClientNeedsMore -> do
              loop
          SendClientFinished cf exts alpn appSecs -> do
              setNegotiatedProto ctx alpn
              setParameters ctx exts
              setApplicationSecrets ctx appSecs
              sendCryptoData ctx Handshake cf
          _ -> error "putServerFinished"

----------------------------------------------------------------

handshakeServer :: Context -> IO ()
handshakeServer ctx = do
    (Initial, ch) <- recvCryptoData ctx
    control <- tlsServerController ctx
    state <- control $ PutClientHello ch
    sh <- case state of
      SendRequestRetry hrr -> do
          sendCryptoData ctx Initial hrr
          (Initial, ch1) <- recvCryptoData ctx
          SendServerHello sh0 exts cipher _ hndSecs <- control $ PutClientHello ch1
          setHandshakeSecrets ctx hndSecs
          setCipher ctx cipher
          setParameters ctx exts
          return sh0
      SendServerHello sh0 exts cipher _ hndSecs -> do
          setHandshakeSecrets ctx hndSecs
          setCipher ctx cipher
          setParameters ctx exts
          return sh0
      _ -> error "handshakeServer"
    sendCryptoData ctx Initial sh
    SendServerFinished sf alpn appSecs <- control GetServerFinished
    setNegotiatedProto ctx alpn
    setApplicationSecrets ctx appSecs
    sendCryptoData ctx Handshake sf
    (Handshake, cf) <- recvCryptoData ctx
    SendSessionTicket nst <- control $ PutClientFinished cf
    sendCryptoData ctx Short nst
    ServerHandshakeDone <- control ExitServer
    clearController ctx

setParameters :: Context -> [ExtensionRaw] -> IO ()
setParameters ctx [ExtensionRaw 0xffa5 params] = do
    let Just plist = decodeParametersList params
    setPeerParameters ctx plist
setParameters _ _ = return ()
