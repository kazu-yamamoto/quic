{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Handshake where

import qualified Network.TLS as TLS
import Network.TLS.QUIC
import qualified UnliftIO.Exception as E

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Info
import Network.QUIC.Logger
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Recovery
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

newtype HndState = HndState
    { hsRecvCnt :: Int  -- number of 'recv' calls since last 'send'
    }

newHndStateRef :: IO (IORef HndState)
newHndStateRef = newIORef HndState { hsRecvCnt = 0 }

sendCompleted :: IORef HndState -> IO ()
sendCompleted hsr = atomicModifyIORef'' hsr $ \hs -> hs { hsRecvCnt = 0 }

recvCompleted :: IORef HndState -> IO Int
recvCompleted hsr = atomicModifyIORef' hsr $ \hs ->
    let cnt = hsRecvCnt hs in (hs { hsRecvCnt = cnt + 1 }, cnt)

rxLevelChanged :: IORef HndState -> IO ()
rxLevelChanged = sendCompleted

----------------------------------------------------------------

sendCryptoData :: Connection -> Output -> IO ()
sendCryptoData = putOutput

recvCryptoData :: Connection -> IO Crypto
recvCryptoData = takeCrypto

recvTLS :: Connection -> IORef HndState -> CryptLevel -> IO (Either TLS.TLSError ByteString)
recvTLS conn hsr level =
    case level of
            CryptInitial           -> go InitialLevel
            CryptMasterSecret      -> failure "QUIC does not receive data < TLS 1.3"
            CryptEarlySecret       -> failure "QUIC does not send early data with TLS library"
            CryptHandshakeSecret   -> go HandshakeLevel
            CryptApplicationSecret -> go RTT1Level
  where
    failure = return . Left . internalError

    go expected = do
        InpHandshake actual bs <- recvCryptoData conn
        if bs == "" then
            return $ Left TLS.Error_EOF
          else if actual /= expected then
            failure $ "encryption level mismatch: expected " ++ show expected ++ " but got " ++ show actual
          else do
            when (isClient conn) $ do
                n <- recvCompleted hsr
                -- Sending ACKs for three times rule
                when ((n `mod` 3) == 1) $
                    sendCryptoData conn $ OutControl HandshakeLevel [] $ return ()
            return $ Right bs

sendTLS :: Connection -> IORef HndState -> [(CryptLevel, ByteString)] -> IO ()
sendTLS conn hsr x = do
    mapM convertLevel x >>= sendCryptoData conn . OutHandshake
    sendCompleted hsr
  where
    convertLevel (CryptInitial, bs) = return (InitialLevel, bs)
    convertLevel (CryptMasterSecret, _) = errorTLS "QUIC does not send data < TLS 1.3"
    convertLevel (CryptEarlySecret, _) = errorTLS "QUIC does not receive early data with TLS library"
    convertLevel (CryptHandshakeSecret, bs) = return (HandshakeLevel, bs)
    convertLevel (CryptApplicationSecret, bs) = return (RTT1Level, bs)

internalError :: String -> TLS.TLSError
internalError msg     = TLS.Error_Protocol (msg, True, TLS.InternalError)
-- unexpectedMessage msg = TLS.Error_Protocol (msg, True, TLS.UnexpectedMessage)

----------------------------------------------------------------

handshakeClient :: ClientConfig -> Connection -> AuthCIDs -> IO (IO ())
handshakeClient conf conn myAuthCIDs = do
    qlogParamsSet conn (ccParameters conf, "local") -- fixme
    handshakeClient' conf conn myAuthCIDs <$> getVersion conn <*> newHndStateRef

handshakeClient' :: ClientConfig -> Connection -> AuthCIDs -> Version -> IORef HndState -> IO ()
handshakeClient' conf conn myAuthCIDs ver hsr = handshaker
  where
    handshaker = clientHandshaker qc conf ver myAuthCIDs setter use0RTT `E.catch` sendCCTLSError
    qc = QUICCallbacks { quicSend = sendTLS conn hsr
                       , quicRecv = recvTLS conn hsr
                       , quicInstallKeys = installKeysClient
                       , quicNotifyExtensions = setPeerParams conn
                       , quicDone = done
                       }
    setter = setResumptionSession conn
    installKeysClient _ctx (InstallEarlyKeys Nothing) = return ()
    installKeysClient _ctx (InstallEarlyKeys (Just (EarlySecretInfo cphr cts))) = do
        setCipher conn RTT0Level cphr
        initializeCoder conn RTT0Level (cts, ServerTrafficSecret "")
        setConnection0RTTReady conn
    installKeysClient _ctx (InstallHandshakeKeys (HandshakeSecretInfo cphr tss)) = do
        setCipher conn HandshakeLevel cphr
        setCipher conn RTT1Level cphr
        initializeCoder conn HandshakeLevel tss
        setEncryptionLevel conn HandshakeLevel
        rxLevelChanged hsr
    installKeysClient ctx (InstallApplicationKeys appSecInf@(ApplicationSecretInfo tss)) = do
        storeNegotiated conn ctx appSecInf
        initializeCoder1RTT conn tss
        setEncryptionLevel conn RTT1Level
        rxLevelChanged hsr
        setConnection1RTTReady conn
        cidInfo <- getNewMyCID conn
        putOutput conn $ OutHandshake [] -- for h3spec testing
        sendFrames conn RTT1Level [NewConnectionID cidInfo 0]
    done _ctx = do
        info <- getConnectionInfo conn
        connDebugLog conn $ bhow info
    use0RTT = ccUse0RTT conf

----------------------------------------------------------------

handshakeServer :: ServerConfig -> Connection -> AuthCIDs -> IO (IO ())
handshakeServer conf conn myAuthCIDs =
    handshakeServer' conf conn myAuthCIDs <$> getVersion conn <*> newHndStateRef

handshakeServer' :: ServerConfig -> Connection -> AuthCIDs -> Version -> IORef HndState -> IO ()
handshakeServer' conf conn myAuthCIDs ver hsr = handshaker
  where
    handshaker = serverHandshaker qc conf ver myAuthCIDs `E.catch` sendCCTLSError
    qc = QUICCallbacks { quicSend = sendTLS conn hsr
                       , quicRecv = recvTLS conn hsr
                       , quicInstallKeys = installKeysServer
                       , quicNotifyExtensions = setPeerParams conn
                       , quicDone = done
                       }
    installKeysServer _ctx (InstallEarlyKeys Nothing) = return ()
    installKeysServer _ctx (InstallEarlyKeys (Just (EarlySecretInfo cphr cts))) = do
        setCipher conn RTT0Level cphr
        initializeCoder conn RTT0Level (cts, ServerTrafficSecret "")
        setConnection0RTTReady conn
    installKeysServer _ctx (InstallHandshakeKeys (HandshakeSecretInfo cphr tss)) = do
        setCipher conn HandshakeLevel cphr
        setCipher conn RTT1Level cphr
        initializeCoder conn HandshakeLevel tss
        setEncryptionLevel conn HandshakeLevel
        rxLevelChanged hsr
    installKeysServer ctx (InstallApplicationKeys appSecInf@(ApplicationSecretInfo tss)) = do
        storeNegotiated conn ctx appSecInf
        initializeCoder1RTT conn tss
        -- will switch to RTT1Level after client Finished
        -- is received and verified
    done ctx = do
        setEncryptionLevel conn RTT1Level
        TLS.getClientCertificateChain ctx >>= setCertificateChain conn
        fire conn (Microseconds 100000) $ do
            let ldcc = connLDCC conn
            discarded0 <- getAndSetPacketNumberSpaceDiscarded ldcc RTT0Level
            unless discarded0 $ dropSecrets conn RTT0Level
            discarded1 <- getAndSetPacketNumberSpaceDiscarded ldcc HandshakeLevel
            unless discarded1 $ do
                dropSecrets conn HandshakeLevel
                onPacketNumberSpaceDiscarded (connLDCC conn) HandshakeLevel
            clearCryptoStream conn HandshakeLevel
            clearCryptoStream conn RTT1Level
        setConnection1RTTReady conn
        setConnectionEstablished conn
--        sendFrames conn RTT1Level [HandshakeDone]
        --
        info <- getConnectionInfo conn
        connDebugLog conn $ bhow info

----------------------------------------------------------------

setPeerParams :: Connection -> TLS.Context -> [ExtensionRaw] -> IO ()
setPeerParams conn _ctx ps0 = do
    ver <- getVersion conn
    let mps | ver == Version1 = getTP extensionID_QuicTransportParameters ps0
            | otherwise       = getTP 0xffa5 ps0
    setPP mps
  where
    getTP _ [] = Nothing
    getTP n (ExtensionRaw extid bs : ps)
      | extid == n = Just bs
      | otherwise  = getTP n ps
    setPP Nothing = return ()
    setPP (Just bs) = do
        let mparams = decodeParameters bs
        case mparams of
          Nothing     -> sendCCParamError
          Just params -> do
              checkAuthCIDs params
              checkInvalid params
              setParams params
              qlogParamsSet conn (params,"remote")

    checkAuthCIDs params = do
        ver <- getVersion conn
        when (ver >= Draft28) $ do
            peerAuthCIDs <- getPeerAuthCIDs conn
            ensure (initialSourceConnectionId params) $ initSrcCID peerAuthCIDs
            when (isClient conn) $ do
                ensure (originalDestinationConnectionId params) $ origDstCID peerAuthCIDs
                ensure (retrySourceConnectionId params) $ retrySrcCID peerAuthCIDs
    ensure _ Nothing = return ()
    ensure v0 v1
      | v0 == v1  = return ()
      | otherwise = sendCCParamError
    checkInvalid params = do
        when (maxUdpPayloadSize params < 1200) sendCCParamError
        when (ackDelayExponent params > 20) sendCCParamError
        when (maxAckDelay params >= 2^(14 :: Int)) sendCCParamError
        when (isServer conn) $ do
            when (isJust $ originalDestinationConnectionId params) sendCCParamError
            when (isJust $ preferredAddress params) sendCCParamError
            when (isJust $ retrySourceConnectionId params) sendCCParamError
            when (isJust $ statelessResetToken params) sendCCParamError
    setParams params = do
        setPeerParameters conn params
        mapM_ (setPeerStatelessResetToken conn) $ statelessResetToken params
        setTxMaxData conn $ initialMaxData params
        setMinIdleTimeout conn $ milliToMicro $ maxIdleTimeout params
        setMaxAckDaley (connLDCC conn) $ milliToMicro $ maxAckDelay params
        setMyMaxStreams conn $ initialMaxStreamsBidi params
        setMyUniMaxStreams conn $ initialMaxStreamsUni params

storeNegotiated :: Connection -> TLS.Context -> ApplicationSecretInfo -> IO ()
storeNegotiated conn ctx appSecInf = do
    appPro <- TLS.getNegotiatedProtocol ctx
    minfo <- TLS.contextGetInformation ctx
    let mode = fromMaybe FullHandshake (minfo >>= TLS.infoTLS13HandshakeMode)
    setNegotiated conn mode appPro appSecInf

----------------------------------------------------------------

sendCCParamError :: IO ()
sendCCParamError = E.throwIO WrongTransportParameter

sendCCTLSError :: TLS.TLSException -> IO ()
sendCCTLSError (TLS.HandshakeFailed (TLS.Error_Misc "WrongTransportParameter")) = closeConnection TransportParameterError "Transport parametter error"
sendCCTLSError e = closeConnection err msg
  where
    tlserr = getErrorCause e
    err = cryptoError $ errorToAlertDescription tlserr
    msg = shortpack $ errorToAlertMessage tlserr

getErrorCause :: TLS.TLSException -> TLS.TLSError
getErrorCause (TLS.HandshakeFailed e) = e
getErrorCause (TLS.Terminated _ _ e)  = e
getErrorCause e =
    let msg = "unexpected TLS exception: " ++ show e
     in TLS.Error_Protocol (msg, True, TLS.InternalError)
