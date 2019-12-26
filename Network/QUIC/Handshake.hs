{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as B
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
recvServerFinishedSendClientFinished control conn = loop (0 :: Int)
  where
    loop n = do
        (HandshakeLevel, eesf, _) <- recvCryptoData conn
        state <- control $ PutServerFinished eesf
        case state of
          ClientNeedsMore -> do
              -- Sending ACKs for three times rule
              -- yield
              when (odd n) $ sendCryptoData conn $ OutControl HandshakeLevel []
              loop (n + 1)
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
    sh <- recvClientHello control conn
    SendServerFinished sf appSecInf <- control GetServerFinished
    setApplicationSecretInfo conn appSecInf
    setEncryptionLevel conn RTT1Level
    sendCryptoData conn $ OutHndServerHello sh sf
    return ()

recvClientHello :: ServerController -> Connection -> IO ServerHello
recvClientHello control conn = loop (0 :: Int)
  where
    loop expectedOff = do
        (InitialLevel, ch, off) <- recvCryptoData conn
        if expectedOff /= off then
            loop expectedOff
          else do
            state <- control $ PutClientHello ch
            let expectedOff' = expectedOff + B.length ch
            case state of
              SendRequestRetry hrr -> do
                  sendCryptoData conn $ OutHndServerHelloR hrr
                  loop expectedOff'
              SendServerHello sh0 exts elySecInf hndSecInf -> do
                  setEarlySecretInfo conn elySecInf
                  setHandshakeSecretInfo conn hndSecInf
                  setEncryptionLevel conn HandshakeLevel
                  setParameters conn exts
                  return sh0
              ServerNeedsMore -> do
                  -- yield
                  loop expectedOff'
              _ -> E.throwIO $ HandshakeFailed "recvClientHello"

setParameters :: Connection -> [ExtensionRaw] -> IO ()
setParameters conn [ExtensionRaw 0xffa5 params] = do
    let Just plist = decodeParametersList params
    setPeerParameters conn plist
setParameters _ _ = return ()
