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
import Network.QUIC.Types

----------------------------------------------------------------

sendCryptoData :: Connection -> Output -> IO ()
sendCryptoData conn out = atomically $ writeTQueue (outputQ conn) out

recvCryptoData :: Connection -> IO (EncryptionLevel, ByteString)
recvCryptoData conn = do
    dat <- atomically $ readTQueue (inputQ conn)
    case dat of
      InpHandshake lvl bs _      -> return (lvl, bs)
      InpTransportError err _ bs -> E.throwIO $ TransportErrorOccurs err bs
      InpApplicationError err bs -> E.throwIO $ ApplicationErrorOccurs err bs
      InpStream{}                -> error "recvCryptoData"

----------------------------------------------------------------

handshakeClient :: ClientConfig -> Connection -> Maybe (StreamID,ByteString)
                -> IO HandshakeMode13
handshakeClient conf conn mEarlyData = do
    control <- clientController conf $ resumptionInfo conn
    setClientController conn control
    sendClientHelloAndRecvServerHello control conn mEarlyData
    recvServerFinishedSendClientFinished control conn

sendClientHelloAndRecvServerHello :: ClientController -> Connection -> Maybe (StreamID,ByteString) -> IO ()
sendClientHelloAndRecvServerHello control conn mEarlyData = do
    SendClientHello ch0 earlySec0 <- control GetClientHello
    setEarlySecret conn earlySec0
    sendCryptoData conn $ OutHndClientHello ch0 mEarlyData
    (InitialLevel, sh0) <- recvCryptoData conn
    state0 <- control $ PutServerHello sh0
    case state0 of
      RecvServerHello cipher hndSecs -> do
          setHandshakeSecrets conn hndSecs
          setCipher conn cipher
      SendClientHello ch1 earlySec1 -> do
          setEarlySecret conn earlySec1
          sendCryptoData conn $ OutHndClientHello ch1 Nothing
          (InitialLevel, sh1) <- recvCryptoData conn
          state1 <- control $ PutServerHello sh1
          case state1 of
            RecvServerHello cipher hndSecs -> do
                setHandshakeSecrets conn hndSecs
                setCipher conn cipher
            _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"
      _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"

recvServerFinishedSendClientFinished :: ClientController -> Connection -> IO HandshakeMode13
recvServerFinishedSendClientFinished control conn = loop
  where
    loop = do
        (HandshakeLevel, eesf) <- recvCryptoData conn
        state <- control $ PutServerFinished eesf
        case state of
          ClientNeedsMore -> do
              loop
          SendClientFinished cf exts alpn appSecs mode -> do
              setNegotiatedProto conn alpn
              setParameters conn exts
              setApplicationSecrets conn appSecs
              sendCryptoData conn $ OutHndClientFinished cf
              return mode
          _ -> E.throwIO $ HandshakeFailed "putServerFinished"

----------------------------------------------------------------

handshakeServer :: ServerConfig -> OrigCID -> Connection -> IO HandshakeMode13
handshakeServer conf origCID conn = do
    control <- serverController conf origCID
    (InitialLevel, ch) <- recvCryptoData conn
    state <- control $ PutClientHello ch
    sh <- case state of
      SendRequestRetry hrr -> do
          sendCryptoData conn $ OutHndServerHelloR hrr
          (InitialLevel, ch1) <- recvCryptoData conn
          SendServerHello sh0 exts cipher earlySec hndSecs <- control $ PutClientHello ch1
          setEarlySecret conn earlySec
          setHandshakeSecrets conn hndSecs
          setCipher conn cipher
          setParameters conn exts
          return sh0
      SendServerHello sh0 exts cipher earlySec hndSecs -> do
          setEarlySecret conn earlySec
          setHandshakeSecrets conn hndSecs
          setCipher conn cipher
          setParameters conn exts
          return sh0
      _ -> E.throwIO $ HandshakeFailed "handshakeServer"
    SendServerFinished sf alpn appSecs <- control GetServerFinished
    setNegotiatedProto conn alpn
    setApplicationSecrets conn appSecs
    sendCryptoData conn $ OutHndServerHello sh sf
    (HandshakeLevel, cf) <- recvCryptoData conn
    SendSessionTicket nst mode <- control $ PutClientFinished cf
    sendCryptoData conn $ OutHndServerNST nst
    ServerHandshakeDone <- control ExitServer
    return mode

setParameters :: Connection -> [ExtensionRaw] -> IO ()
setParameters conn [ExtensionRaw 0xffa5 params] = do
    let Just plist = decodeParametersList params
    setPeerParameters conn plist
setParameters _ _ = return ()
