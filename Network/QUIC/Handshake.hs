{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

import qualified Control.Exception as E
import Data.ByteString
import qualified Data.ByteString.Short as Short
import Data.IORef
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

newtype HndState = HndState
    { hsRecvCnt :: Int  -- number of 'recv' calls since last 'send'
    }

newHndStateRef :: IO (IORef HndState)
newHndStateRef = newIORef HndState { hsRecvCnt = 0 }

sendCompleted :: IORef HndState -> IO ()
sendCompleted hsr = atomicModifyIORef' hsr $ \hs ->
    (hs { hsRecvCnt = 0 }, ())

recvCompleted :: IORef HndState -> IO Int
recvCompleted hsr = atomicModifyIORef' hsr $ \hs ->
    let cnt = hsRecvCnt hs in (hs { hsRecvCnt = cnt + 1 }, cnt)

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

quicRecvTLS :: Connection -> IORef HndState -> CryptLevel -> IO ByteString
quicRecvTLS conn hsr level = do
    let expected = case level of
            CryptInitial           -> InitialLevel
            CryptMasterSecret      -> error "QUIC does not receive data < TLS 1.3"
            CryptEarlySecret       -> error "QUIC does not send early data with TLS library"
            CryptHandshakeSecret   -> HandshakeLevel
            CryptApplicationSecret -> RTT1Level
    (actual, bs) <- recvCryptoData conn
    when (actual /= expected) $
        error $ "encryption level mismatch: expected " ++ show expected ++
                " but got " ++ show actual
    n <- recvCompleted hsr
    case expected of
        InitialLevel | isServer conn ->
            -- To prevent CI0'
            when (n > 0) $
                sendCryptoData conn $ OutControl InitialLevel []
        HandshakeLevel | isClient conn ->
            -- Sending ACKs for three times rule
            when ((n `mod` 3) == 0) $
                sendCryptoData conn $ OutControl HandshakeLevel []
        _ -> return ()
    return bs
-- fixme: should use better exceptions

quicSendTLS :: Connection -> IORef HndState -> [(CryptLevel, ByteString)] -> IO ()
quicSendTLS conn hsr x = do
    sendCryptoData conn $ OutHandshake $ fmap convertLevel x
    sendCompleted hsr
  where
    convertLevel (CryptInitial, bs) = (InitialLevel, bs)
    convertLevel (CryptMasterSecret, _) = error "QUIC does not send data < TLS 1.3"
    convertLevel (CryptEarlySecret, _) = error "QUIC does not receive early data with TLS library"
    convertLevel (CryptHandshakeSecret, bs) = (HandshakeLevel, bs)
    convertLevel (CryptApplicationSecret, bs) = (RTT1Level, bs)
-- fixme: should use better exceptions

----------------------------------------------------------------

handshakeClient :: ClientConfig -> Connection -> IO ()
handshakeClient conf conn = do
    ver <- getVersion conn
    hsr <- newHndStateRef
    let sendEarlyData = isJust $ ccEarlyData conf
        qc = QuicCallbacks { quicSend = quicSendTLS conn hsr
                           , quicRecv = quicRecvTLS conn hsr
                           , quicNotifySecretEvent = quicSyncC
                           , quicNotifyExtensions = setPeerParams conn
                           }
    control <- clientController qc conf ver (setResumptionSession conn) sendEarlyData
    setClientController conn control
    state <- control GetClientHello
    case state of
        SendClientFinished -> return ()
        _ -> E.throwIO $ HandshakeFailed "handshakeClient"

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

----------------------------------------------------------------

handshakeServer :: ServerConfig -> OrigCID -> Connection -> IO ()
handshakeServer conf origCID conn = do
    ver <- getVersion conn
    hsr <- newHndStateRef
    let qc = QuicCallbacks { quicSend = quicSendTLS conn hsr
                           , quicRecv = quicRecvTLS conn hsr
                           , quicNotifySecretEvent = quicSyncS
                           , quicNotifyExtensions = setPeerParams conn
                           }
    control <- serverController qc conf ver origCID
    setServerController conn control
    state <- control PutClientHello
    case state of
        SendServerFinished -> return ()
        _ -> E.throwIO $ HandshakeFailed "handshakeServer"

  where
    quicSyncS (SyncEarlySecret mEarlySecInf) =
        setEarlySecretInfo conn mEarlySecInf
    quicSyncS (SyncHandshakeSecret hndSecInf) = do
        setHandshakeSecretInfo conn hndSecInf
        setEncryptionLevel conn HandshakeLevel
    quicSyncS (SyncApplicationSecret appSecInf) = do
        setApplicationSecretInfo conn appSecInf
        setEncryptionLevel conn RTT1Level

setPeerParams :: Connection -> [ExtensionRaw] -> IO ()
setPeerParams conn [ExtensionRaw extid params]
  | extid == extensionID_QuicTransportParameters = do
        let mplist = decodeParametersList params
        case mplist of
          Nothing    -> connDebugLog conn "cannot decode parameters"
          Just plist -> setPeerParameters conn plist
setPeerParams _ _ = return ()
