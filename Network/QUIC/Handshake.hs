{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

import qualified Control.Exception as E
import Data.ByteString
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

sendCryptoData :: Connection -> Output -> IO ()
sendCryptoData = putOutput

recvCryptoData :: Connection -> IO (EncryptionLevel, ByteString)
recvCryptoData conn = do
    dat <- takeCrypto conn
    case dat of
      InpHandshake lvl bs        -> return (lvl, bs)
      InpVersion (Just ver)      -> E.throwIO $ NextVersion ver
      InpVersion Nothing         -> E.throwIO   VersionNegotiationFailed
      InpError e                 -> E.throwIO e
      InpTransportError err _ bs -> E.throwIO $ TransportErrorOccurs err bs
      InpApplicationError err bs -> E.throwIO $ ApplicationErrorOccurs err bs
      InpStream{}                -> E.throwIO   MustNotReached

----------------------------------------------------------------

handshakeClient :: ClientConfig -> Connection -> IO ()
handshakeClient conf conn = do
    ver <- getVersion conn
    let sendEarlyData = isJust $ ccEarlyData conf
        qc = QuicCallbacks { quicNotifyExtensions = setPeerParams conn
                           }
    control <- clientController qc conf ver (setResumptionSession conn) sendEarlyData
    setClientController conn control
    sendClientHelloAndRecvServerHello control conn $ ccEarlyData conf
    recvServerFinishedSendClientFinished control conn

sendClientHelloAndRecvServerHello :: ClientController -> Connection -> Maybe (StreamId,ByteString) -> IO ()
sendClientHelloAndRecvServerHello control conn mEarlyData = do
    SendClientHello ch0 mEarlySecInf <- control GetClientHello
    setEarlySecretInfo conn mEarlySecInf
    sendCryptoData conn $ OutHndClientHello ch0 mEarlyData
    (InitialLevel, sh0) <- recvCryptoData conn
    state0 <- control $ PutServerHello sh0
    case state0 of
      RecvServerHello hndSecInf -> do
          setHandshakeSecretInfo conn hndSecInf
          setEncryptionLevel conn HandshakeLevel
      SendClientHello ch1 mEarlySecInf1 -> do
          setEarlySecretInfo conn mEarlySecInf1
          sendCryptoData conn $ OutHndClientHello ch1 Nothing
          (InitialLevel, sh1) <- recvCryptoData conn
          state1 <- control $ PutServerHello sh1
          case state1 of
            RecvServerHello hndSecInf -> do
                setHandshakeSecretInfo conn hndSecInf
                setEncryptionLevel conn HandshakeLevel
            _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"
      _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"

recvServerFinishedSendClientFinished :: ClientController -> Connection -> IO ()
recvServerFinishedSendClientFinished control conn = loop (1 :: Int)
  where
    loop n = do
        (HandshakeLevel, eesf) <- recvCryptoData conn
        state <- control $ PutServerFinished eesf
        case state of
          ClientNeedsMore -> do
              -- Sending ACKs for three times rule
              when ((n `mod` 3) == 2) $
                  sendCryptoData conn $ OutControl HandshakeLevel []
              loop (n + 1)
          SendClientFinished cf appSecInf -> do
              setApplicationSecretInfo conn appSecInf
              setEncryptionLevel conn RTT1Level
              sendCryptoData conn $ OutHndClientFinished cf
          _ -> E.throwIO $ HandshakeFailed "putServerFinished"

----------------------------------------------------------------

handshakeServer :: ServerConfig -> OrigCID -> Connection -> IO ()
handshakeServer conf origCID conn = do
    ver <- getVersion conn
    let qc = QuicCallbacks { quicNotifyExtensions = setPeerParams conn
                           }
    control <- serverController qc conf ver origCID
    setServerController conn control
    sh <- recvClientHello control conn
    SendServerFinished sf appSecInf <- control GetServerFinished
    setApplicationSecretInfo conn appSecInf
    setEncryptionLevel conn RTT1Level
    sendCryptoData conn $ OutHndServerHello sh sf
    return ()

recvClientHello :: ServerController -> Connection -> IO ServerHello
recvClientHello control conn = loop
  where
    loop = do
        (InitialLevel, ch) <- recvCryptoData conn
        state <- control $ PutClientHello ch
        case state of
          SendRequestRetry hrr -> do
              sendCryptoData conn $ OutHndServerHelloR hrr
              loop
          SendServerHello sh0 mEarlySecInf hndSecInf -> do
              setEarlySecretInfo conn mEarlySecInf
              setHandshakeSecretInfo conn hndSecInf
              setEncryptionLevel conn HandshakeLevel
              return sh0
          ServerNeedsMore -> do
              -- To prevent CI0' above.
              sendCryptoData conn $ OutControl InitialLevel []
              loop
          _ -> E.throwIO $ HandshakeFailed "recvClientHello"

setPeerParams :: Connection -> [ExtensionRaw] -> IO ()
setPeerParams conn [ExtensionRaw extid params]
  | extid == extensionID_QuicTransportParameters = do
        let mplist = decodeParametersList params
        case mplist of
          Nothing    -> connDebugLog conn "cannot decode parameters"
          Just plist -> setPeerParameters conn plist
setPeerParams _ _ = return ()
