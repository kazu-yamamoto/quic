{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

import qualified Control.Exception as E
import Data.ByteString
import qualified Data.ByteString.Short as Short
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
      InpTransportError err _ bs
          | err == NoError       -> return (RTT1Level, Short.fromShort bs) -- fixme: RTT1Level
          | otherwise            -> E.throwIO $ TransportErrorOccurs err bs
      InpApplicationError err bs -> E.throwIO $ ApplicationErrorOccurs err bs
      InpStream{}                -> E.throwIO   MustNotReached

quicRecvTLS :: Connection -> CryptLevel -> IO ByteString
quicRecvTLS conn CryptInitial           = do { (InitialLevel, bs) <- recvCryptoData conn; return bs }
quicRecvTLS _    CryptMasterSecret      = error "QUIC does not receive data < TLS 1.3"
quicRecvTLS conn CryptEarlySecret       = do { (HandshakeLevel, bs) <- recvCryptoData conn; return bs }
quicRecvTLS conn CryptHandshakeSecret   = do { (HandshakeLevel, bs) <- recvCryptoData conn; return bs }
quicRecvTLS conn CryptApplicationSecret = do { (RTT1Level, bs) <- recvCryptoData conn; return bs }
-- fixme: should use better exceptions / avoid pattern match

----------------------------------------------------------------

handshakeClient :: ClientConfig -> Connection -> IO ()
handshakeClient conf conn = do
    ver <- getVersion conn
    let sendEarlyData = isJust $ ccEarlyData conf
        qc = QuicCallbacks { quicRecv = quicRecvTLS conn
                           , quicNotifySecretEvent = quicSyncC
                           , quicNotifyExtensions = setPeerParams conn
                           }
    control <- clientController qc conf ver (setResumptionSession conn) sendEarlyData
    setClientController conn control
    sendClientHelloAndRecvServerHello control conn $ ccEarlyData conf
    recvServerFinishedSendClientFinished control conn

  where
    quicSyncC (SyncEarlySecret mEarlySecInf) =
        setEarlySecretInfo conn mEarlySecInf
    quicSyncC (SyncHandshakeSecret hndSecInf) = do
        setHandshakeSecretInfo conn hndSecInf
        setEncryptionLevel conn HandshakeLevel
    quicSyncC (SyncApplicationSecret appSecInf) = do
        setApplicationSecretInfo conn appSecInf
        setEncryptionLevel conn RTT1Level

sendClientHelloAndRecvServerHello :: ClientController -> Connection -> Maybe (StreamId,ByteString) -> IO ()
sendClientHelloAndRecvServerHello control conn mEarlyData = do
    SendClientHello ch0 <- control GetClientHello
    sendCryptoData conn $ OutHndClientHello ch0 mEarlyData
    state0 <- control PutServerHello
    case state0 of
      RecvServerHello -> return ()
      SendClientHello ch1 -> do
          sendCryptoData conn $ OutHndClientHello ch1 Nothing
          state1 <- control PutServerHello
          case state1 of
            RecvServerHello -> return ()
            _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"
      _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"

recvServerFinishedSendClientFinished :: ClientController -> Connection -> IO ()
recvServerFinishedSendClientFinished control conn = loop (1 :: Int)
  where
    loop _n = do
        state <- control PutServerFinished
        case state of
          -- fixme: not sure we need to keep this
          --
          -- ClientNeedsMore -> do
          --     -- Sending ACKs for three times rule
          --     when ((n `mod` 3) == 2) $
          --         sendCryptoData conn $ OutControl HandshakeLevel []
          --     loop (n + 1)
          SendClientFinished cf ->
              sendCryptoData conn $ OutHndClientFinished cf
          _ -> E.throwIO $ HandshakeFailed "putServerFinished"

----------------------------------------------------------------

handshakeServer :: ServerConfig -> OrigCID -> Connection -> IO ()
handshakeServer conf origCID conn = do
    ver <- getVersion conn
    let qc = QuicCallbacks { quicRecv = quicRecvTLS conn
                           , quicNotifySecretEvent = quicSyncS
                           , quicNotifyExtensions = setPeerParams conn
                           }
    control <- serverController qc conf ver origCID
    setServerController conn control
    sh <- recvClientHello control conn
    SendServerFinished sf <- control GetServerFinished
    sendCryptoData conn $ OutHndServerHello sh sf
    return ()

  where
    quicSyncS (SyncEarlySecret mEarlySecInf) =
        setEarlySecretInfo conn mEarlySecInf
    quicSyncS (SyncHandshakeSecret hndSecInf) = do
        setHandshakeSecretInfo conn hndSecInf
        setEncryptionLevel conn HandshakeLevel
    quicSyncS (SyncApplicationSecret appSecInf) = do
        setApplicationSecretInfo conn appSecInf
        setEncryptionLevel conn RTT1Level

recvClientHello :: ServerController -> Connection -> IO ServerHello
recvClientHello control conn = loop
  where
    loop = do
        state <- control PutClientHello
        case state of
          SendRequestRetry hrr -> do
              sendCryptoData conn $ OutHndServerHelloR hrr
              loop
          SendServerHello sh0 -> return sh0
          -- fixme: not sure we need to keep this
          --
          -- ServerNeedsMore -> do
          --     -- To prevent CI0' above.
          --     sendCryptoData conn $ OutControl InitialLevel []
          --     loop
          _ -> E.throwIO $ HandshakeFailed "recvClientHello"

setPeerParams :: Connection -> [ExtensionRaw] -> IO ()
setPeerParams conn [ExtensionRaw extid params]
  | extid == extensionID_QuicTransportParameters = do
        let mplist = decodeParametersList params
        case mplist of
          Nothing    -> connDebugLog conn "cannot decode parameters"
          Just plist -> setPeerParameters conn plist
setPeerParams _ _ = return ()
