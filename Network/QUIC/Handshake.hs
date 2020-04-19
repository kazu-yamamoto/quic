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

quicSendTLS :: Connection -> [(CryptLevel, ByteString)] -> IO ()
quicSendTLS conn = sendCryptoData conn . OutHandshake . fmap convertLevel
  where
    convertLevel (CryptInitial, bs) = (InitialLevel, bs)
    convertLevel (CryptMasterSecret, _) = error "QUIC does not send data < TLS 1.3"
    convertLevel (CryptEarlySecret, bs) = (RTT0Level, bs)
    convertLevel (CryptHandshakeSecret, bs) = (HandshakeLevel, bs)
    convertLevel (CryptApplicationSecret, bs) = (RTT1Level, bs)
-- fixme: should use better exceptions

----------------------------------------------------------------

handshakeClient :: ClientConfig -> Connection -> IO ()
handshakeClient conf conn = do
    ver <- getVersion conn
    let sendEarlyData = isJust $ ccEarlyData conf
        qc = QuicCallbacks { quicSend = quicSendTLS conn
                           , quicRecv = quicRecvTLS conn
                           , quicNotifySecretEvent = quicSyncC
                           , quicNotifyExtensions = setPeerParams conn
                           }
    control <- clientController qc conf ver (setResumptionSession conn) sendEarlyData
    setClientController conn control
    sendClientHelloAndRecvServerHello control conn
    recvServerFinishedSendClientFinished control conn

  where
    quicSyncC (SyncEarlySecret mEarlySecInf) = do
        setEarlySecretInfo conn mEarlySecInf
        sendCryptoData conn $ OutEarlyData (ccEarlyData conf)
    quicSyncC (SyncHandshakeSecret hndSecInf) = do
        setHandshakeSecretInfo conn hndSecInf
        setEncryptionLevel conn HandshakeLevel
    quicSyncC (SyncApplicationSecret appSecInf) = do
        setApplicationSecretInfo conn appSecInf
        setEncryptionLevel conn RTT1Level

sendClientHelloAndRecvServerHello :: ClientController -> Connection -> IO ()
sendClientHelloAndRecvServerHello control _conn = do
    SendClientHello <- control GetClientHello
    state0 <- control PutServerHello
    case state0 of
      RecvServerHello -> return ()
      SendClientHello -> do
          state1 <- control PutServerHello
          case state1 of
            RecvServerHello -> return ()
            _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"
      _ -> E.throwIO $ HandshakeFailed "sendClientHelloAndRecvServerHello"

recvServerFinishedSendClientFinished :: ClientController -> Connection -> IO ()
recvServerFinishedSendClientFinished control _conn = loop (1 :: Int)
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
          SendClientFinished -> return ()
          _ -> E.throwIO $ HandshakeFailed "putServerFinished"

----------------------------------------------------------------

handshakeServer :: ServerConfig -> OrigCID -> Connection -> IO ()
handshakeServer conf origCID conn = do
    ver <- getVersion conn
    let qc = QuicCallbacks { quicSend = quicSendTLS conn
                           , quicRecv = quicRecvTLS conn
                           , quicNotifySecretEvent = quicSyncS
                           , quicNotifyExtensions = setPeerParams conn
                           }
    control <- serverController qc conf ver origCID
    setServerController conn control
    recvClientHello control conn
    SendServerFinished <- control GetServerFinished
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

recvClientHello :: ServerController -> Connection -> IO ()
recvClientHello control _conn = loop
  where
    loop = do
        state <- control PutClientHello
        case state of
          SendRequestRetry -> loop
          SendServerHello -> return ()
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
