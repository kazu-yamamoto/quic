{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

import Control.Concurrent
import qualified Control.Exception as E
import Data.ByteString
import qualified Network.TLS as TLS
import Network.TLS.QUIC

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
import Network.QUIC.Timeout
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
        if actual /= expected then
            failure $ "encryption level mismatch: expected " ++ show expected ++ " but got " ++ show actual
          else do
            when (isClient conn) $ do
                n <- recvCompleted hsr
                -- Sending ACKs for three times rule
                when ((n `mod` 3) == 1) $
                    sendCryptoData conn $ OutControl HandshakeLevel []
            return (Right bs)

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

internalError, unexpectedMessage :: String -> TLS.TLSError
internalError msg     = TLS.Error_Protocol (msg, True, TLS.InternalError)
unexpectedMessage msg = TLS.Error_Protocol (msg, True, TLS.UnexpectedMessage)

----------------------------------------------------------------

handshakeClient :: ClientConfig -> Connection -> AuthCIDs -> IO ()
handshakeClient conf conn myAuthCIDs = do
    ver <- getVersion conn
    hsr <- newHndStateRef
    let use0RTT = ccUse0RTT conf
        qc = QUICCallbacks { quicSend = sendTLS conn hsr
                           , quicRecv = recvTLS conn hsr
                           , quicInstallKeys = installKeysClient hsr
                           , quicNotifyExtensions = setPeerParams conn
                           , quicDone = done
                           }
        setter = setResumptionSession conn
        handshaker = clientHandshaker qc conf ver myAuthCIDs setter use0RTT
    tid <- forkIO (handshaker `E.catch` tell)
    qlogParamsSet conn (confParameters (ccConfig conf), "local")
    setKillHandshaker conn tid
    if use0RTT then
       wait0RTTReady conn
     else
       wait1RTTReady conn
  where
    tell (TLS.HandshakeFailed (TLS.Error_Misc _)) = return () -- thread blocked
    tell e = notifyPeer conn $ getErrorCause e
    installKeysClient _ _ctx (InstallEarlyKeys Nothing) = return ()
    installKeysClient _ _ctx (InstallEarlyKeys (Just (EarlySecretInfo cphr cts))) = do
        setCipher conn RTT0Level cphr
        initializeCoder conn RTT0Level (cts, ServerTrafficSecret "")
        setConnection0RTTReady conn
    installKeysClient hsr _ctx (InstallHandshakeKeys (HandshakeSecretInfo cphr tss)) = do
        setCipher conn HandshakeLevel cphr
        setCipher conn RTT1Level cphr
        initializeCoder conn HandshakeLevel tss
        setEncryptionLevel conn HandshakeLevel
        rxLevelChanged hsr
    installKeysClient hsr ctx (InstallApplicationKeys appSecInf@(ApplicationSecretInfo tss)) = do
        storeNegotiated conn ctx appSecInf
        initializeCoder conn RTT1Level tss
        setEncryptionLevel conn RTT1Level
        rxLevelChanged hsr
        setConnection1RTTReady conn
        cidInfo <- getNewMyCID conn
        let ncid = NewConnectionID cidInfo 0
        putOutput conn $ OutHandshake [] -- for h3spec testing
        putOutput conn $ OutControl RTT1Level [ncid]
    done _ctx = do
        info <- getConnectionInfo conn
        connDebugLog conn $ bhow info

----------------------------------------------------------------

handshakeServer :: ServerConfig -> Connection -> AuthCIDs -> IO ()
handshakeServer conf conn myAuthCIDs = do
    ver <- getVersion conn
    hsr <- newHndStateRef
    let qc = QUICCallbacks { quicSend = sendTLS conn hsr
                           , quicRecv = recvTLS conn hsr
                           , quicInstallKeys = installKeysServer hsr
                           , quicNotifyExtensions = setPeerParams conn
                           , quicDone = done
                           }
        handshaker = serverHandshaker qc conf ver myAuthCIDs
    tid <- forkIO (handshaker `E.catch` tell)
    setKillHandshaker conn tid
    wait1RTTReady conn
  where
    tell (TLS.HandshakeFailed (TLS.Error_Misc _)) = return () -- thread blocked
    tell e = notifyPeer conn $ getErrorCause e
    installKeysServer _ _ctx (InstallEarlyKeys Nothing) = return ()
    installKeysServer _ _ctx (InstallEarlyKeys (Just (EarlySecretInfo cphr cts))) = do
        setCipher conn RTT0Level cphr
        initializeCoder conn RTT0Level (cts, ServerTrafficSecret "")
        setConnection0RTTReady conn
    installKeysServer hsr _ctx (InstallHandshakeKeys (HandshakeSecretInfo cphr tss)) = do
        setCipher conn HandshakeLevel cphr
        setCipher conn RTT1Level cphr
        initializeCoder conn HandshakeLevel tss
        setEncryptionLevel conn HandshakeLevel
        rxLevelChanged hsr
    installKeysServer _ ctx (InstallApplicationKeys appSecInf@(ApplicationSecretInfo tss)) = do
        storeNegotiated conn ctx appSecInf
        initializeCoder conn RTT1Level tss
        -- will switch to RTT1Level after client Finished
        -- is received and verified
    done ctx = do
        setEncryptionLevel conn RTT1Level
        TLS.getClientCertificateChain ctx >>= setCertificateChain conn
        clearKillHandshaker conn
        onPacketNumberSpaceDiscarded (connLDCC conn) HandshakeLevel
        fire (Microseconds 100000) $ do
            dropSecrets conn RTT0Level
            dropSecrets conn HandshakeLevel
            clearCryptoStream conn HandshakeLevel
            clearCryptoStream conn RTT1Level
        setConnection1RTTReady conn
        setConnectionEstablished conn
--        putOutput conn $ OutControl RTT1Level [HandshakeDone]
        --
        info <- getConnectionInfo conn
        connDebugLog conn $ bhow info

setPeerParams :: Connection -> TLS.Context -> [ExtensionRaw] -> IO ()
setPeerParams conn _ctx [ExtensionRaw extid bs]
  | extid == extensionID_QuicTransportParameters = do
        let mparams = decodeParameters bs
        case mparams of
          Nothing     -> err
          Just params -> do
              checkAuthCIDs params
              checkInvalid params
              setParams params
              qlogParamsSet conn (params,"remote")
  where
    err = do
        sendConnectionClose conn $ ConnectionCloseQUIC TransportParameterError 0 ""
        exitConnection conn $ TransportErrorOccurs TransportParameterError ""
        -- converted into Error_Misc and ignored in "tell"
        E.throwIO TransportParameterError
    checkAuthCIDs params = do
        ver <- getVersion conn
        when (ver >= Draft28) $ do
            peerAuthCIDs <- getPeerAuthCIDs conn
            check (initialSourceConnectionId params) $ initSrcCID peerAuthCIDs
            when (isClient conn) $ do
                check (originalDestinationConnectionId params) $ origDstCID peerAuthCIDs
                check (retrySourceConnectionId params) $ retrySrcCID peerAuthCIDs
    check _ Nothing = return ()
    check v0 v1
      | v0 == v1  = return ()
      | otherwise = err
    checkInvalid params = do
        when (maxUdpPayloadSize params < 1200) err
        when (ackDelayExponent params > 20) err
        when (maxAckDelay params >= 2^(14 :: Int)) err
        when (isServer conn) $ do
            when (isJust $ originalDestinationConnectionId params) err
            when (isJust $ preferredAddress params) err
            when (isJust $ retrySourceConnectionId params) err
            when (isJust $ statelessResetToken params) err
    setParams params = do
        setPeerParameters conn params
        case statelessResetToken params of
          Nothing  -> return ()
          Just srt -> setPeerStatelessResetToken conn srt
        setTxMaxData conn $ initialMaxData params
        setMinIdleTimeout conn $ milliToMicro $ maxIdleTimeout params
        setMaxAckDaley (connLDCC conn) $ milliToMicro $ maxAckDelay params
        setMyMaxStreams conn $ initialMaxStreamsBidi params
        setMyUniMaxStreams conn $ initialMaxStreamsUni params
setPeerParams _ _ _ = return ()

getErrorCause :: TLS.TLSException -> TLS.TLSError
getErrorCause (TLS.HandshakeFailed e) = e
getErrorCause (TLS.Terminated _ _ e) = e
getErrorCause e =
    let msg = "unexpected TLS exception: " ++ show e
     in TLS.Error_Protocol (msg, True, TLS.InternalError)

notifyPeer :: Connection -> TLS.TLSError -> IO ()
notifyPeer conn err = do
    sendConnectionClose conn frame
    exitConnection conn $ HandshakeFailed ad
  where
    ad = errorToAlertDescription err
    frame = ConnectionCloseQUIC (CryptoError ad) 0 ""

storeNegotiated :: Connection -> TLS.Context -> ApplicationSecretInfo -> IO ()
storeNegotiated conn ctx appSecInf = do
    appPro <- TLS.getNegotiatedProtocol ctx
    minfo <- TLS.contextGetInformation ctx
    let mode = fromMaybe FullHandshake (minfo >>= TLS.infoTLS13HandshakeMode)
    setNegotiated conn mode appPro appSecInf

