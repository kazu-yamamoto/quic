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
    SendClientHello ch0 _ <- tlsClientControl ctx $ GetClientHello
    sendCryptoData ctx Initial ch0
    (Initial, sh0) <- recvCryptoData ctx
    ctl0 <- tlsClientControl ctx $ PutServerHello sh0
    case ctl0 of
      RecvServerHello cipher hndSecs -> do
          setHandshakeSecrets ctx hndSecs
          setCipher ctx cipher
      SendClientHello ch1 _ -> do
          sendCryptoData ctx Initial ch1
          (Initial, sh1) <- recvCryptoData ctx
          ctl1 <- tlsClientControl ctx $ PutServerHello sh1
          case ctl1 of
            RecvServerHello cipher hndSecs -> do
                setHandshakeSecrets ctx hndSecs
                setCipher ctx cipher
            _ -> error "sendClientHelloAndRecvServerHello"
      _ -> error "sendClientHelloAndRecvServerHello"

recvServerFinishedSendClientFinished :: Context -> IO ()
recvServerFinishedSendClientFinished ctx = loop
  where
    loop = do
        (Handshake, eesf) <- recvCryptoData ctx
        ctl <- tlsClientControl ctx $ PutServerFinished eesf
        case ctl of
          ClientNeedsMore -> do
              loop
          SendClientFinished cf exts alpn appSecs -> do
              setNegotiatedProto ctx alpn
              case exts of
                [ExtensionRaw 0xffa5 params] -> do
                    let Just plist = decodeParametersList params
                    setPeerParameters ctx plist
                _ -> return ()
              setApplicationSecrets ctx appSecs
              sendCryptoData ctx Handshake cf
          _ -> error "putServerFinished"

----------------------------------------------------------------

handshakeServer :: Context -> IO ()
handshakeServer _ctx = undefined
