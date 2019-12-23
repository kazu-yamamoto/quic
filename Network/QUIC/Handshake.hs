{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

import Control.Concurrent.STM
import qualified Control.Exception as E
import Data.ByteString hiding (putStrLn)
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

sendCryptoData :: Connection -> Output -> IO ()
sendCryptoData conn out = atomically $ writeTQueue (outputQ conn) out

recvCryptoData :: Connection -> IO (EncryptionLevel, ByteString, Offset)
recvCryptoData conn = do
    dat <- atomically $ readTQueue (cryptoQ conn)
    case dat of
      InpHandshake lvl bs off _  -> return (lvl, bs, off)
      InpTransportError err _ bs -> E.throwIO $ TransportErrorOccurs err bs
      InpApplicationError err bs -> E.throwIO $ ApplicationErrorOccurs err bs
      InpStream{}                -> error "recvCryptoData"

----------------------------------------------------------------

handshakeClient :: ClientConfig -> Connection -> IO ()
handshakeClient conf conn = do
    let sendEarlyData = isJust $ ccEarlyData conf
    control <- clientController conf (setResumptionSession conn) sendEarlyData
    setClientController conn control
    sendClientHelloAndRecvServerHello control conn $ ccEarlyData conf
    recvServerFinishedSendClientFinished control conn

sendClientHelloAndRecvServerHello :: ClientController -> Connection -> Maybe (StreamID,ByteString) -> IO ()
sendClientHelloAndRecvServerHello control conn mEarlyData = do
    SendClientHello ch0 mEarlySecInf <- control GetClientHello
    setEarlySecretInfo conn mEarlySecInf
    sendCryptoData conn $ OutHndClientHello ch0 mEarlyData
    (InitialLevel, sh0, _) <- recvCryptoData conn
    state0 <- control $ PutServerHello sh0
    case state0 of
      RecvServerHello hndSecInf -> do
          setHandshakeSecretInfo conn hndSecInf
          setEncryptionLevel conn HandshakeLevel
      SendClientHello ch1 mEarlySecInf1 -> do
          setEarlySecretInfo conn mEarlySecInf1
          sendCryptoData conn $ OutHndClientHello ch1 Nothing
          (InitialLevel, sh1, _) <- recvCryptoData conn
          state1 <- control $ PutServerHello sh1
          case state1 of
            RecvServerHello hndSecInf -> do
                setHandshakeSecretInfo conn hndSecInf
                setEncryptionLevel conn HandshakeLevel
            _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"
      _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"

recvServerFinishedSendClientFinished :: ClientController -> Connection -> IO ()
recvServerFinishedSendClientFinished control conn = loop
  where
    loop = do
        (HandshakeLevel, eesf, _) <- recvCryptoData conn
        state <- control $ PutServerFinished eesf
        case state of
          ClientNeedsMore -> do
              loop
          SendClientFinished cf exts appSecInf -> do
              setApplicationSecretInfo conn appSecInf
              setEncryptionLevel conn RTT1Level
              setParameters conn exts
              sendCryptoData conn $ OutHndClientFinished cf
          _ -> E.throwIO $ HandshakeFailed "putServerFinished"

----------------------------------------------------------------

handshakeServer :: ServerConfig -> OrigCID -> Connection -> IO ()
handshakeServer conf origCID conn = do
    control <- serverController conf origCID
    setServerController conn control
    sh <- recvClientHello control conn True
    SendServerFinished sf appSecInf <- control GetServerFinished
    setApplicationSecretInfo conn appSecInf
    setEncryptionLevel conn RTT1Level
    sendCryptoData conn $ OutHndServerHello sh sf
    return ()

recvClientHello :: ServerController -> Connection -> Bool -> IO ServerHello
recvClientHello control conn reqZero = do
    (InitialLevel, ch, off) <- recvCryptoData conn
    -- fixme: TLS hello retry: off /= 0
    -- fixme: TLS hello fragment : off /= 0
--    when (reqZero && off /= 0) $ E.throwIO $ HandshakeFailed "CH fragment"
    if not reqZero && off == 0 then
        recvClientHello control conn False
      else do
        state <- control $ PutClientHello ch
        case state of
          SendRequestRetry hrr -> do
              sendCryptoData conn $ OutHndServerHelloR hrr
              recvClientHello control conn True
          SendServerHello sh0 exts elySecInf hndSecInf -> do
              setEarlySecretInfo conn elySecInf
              setHandshakeSecretInfo conn hndSecInf
              setEncryptionLevel conn HandshakeLevel
              setParameters conn exts
              return sh0
          ServerNeedsMore ->
              recvClientHello control conn False
          _ -> E.throwIO $ HandshakeFailed "recvClientHello"

setParameters :: Connection -> [ExtensionRaw] -> IO ()
setParameters conn [ExtensionRaw 0xffa5 params] = do
    let Just plist = decodeParametersList params
    setPeerParameters conn plist
setParameters _ _ = return ()
