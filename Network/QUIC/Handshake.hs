{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

import Control.Concurrent
import qualified Control.Exception as E
import Data.ByteString
import Data.IORef
import qualified Network.TLS as TLS
import Network.TLS.QUIC


import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Info
import Network.QUIC.Parameters
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
sendCompleted hsr = atomicModifyIORef' hsr $ \hs ->
    (hs { hsRecvCnt = 0 }, ())

recvCompleted :: IORef HndState -> IO Int
recvCompleted hsr = atomicModifyIORef' hsr $ \hs ->
    let cnt = hsRecvCnt hs in (hs { hsRecvCnt = cnt + 1 }, cnt)

rxLevelChanged :: IORef HndState -> IO ()
rxLevelChanged = sendCompleted

----------------------------------------------------------------

sendCryptoData :: Connection -> Output -> IO ()
sendCryptoData = putOutput

recvCryptoData :: Connection -> IO (Either TLS.TLSError (EncryptionLevel, ByteString))
recvCryptoData conn = do
    dat <- takeCrypto conn
    case dat of
      InpHandshake lvl bs        -> return $ Right (lvl, bs)
      -- When possible we return normal TLS errors to TLS callbacks.
      InpTransportError err _ bs
          | err == NoError       -> return $ Left TLS.Error_EOF
          | otherwise            ->
              let msg | bs == ""  = "received transport error during TLS handshake: " ++ show err
                      | otherwise = "received transport error during TLS handshake: " ++ show err ++ ", reason=" ++ show bs
               in return $ Left $ unexpectedMessage msg
      InpError e                 -> E.throwIO e
      InpApplicationError err bs -> E.throwIO $ ApplicationErrorOccurs err bs
      InpNewStream{}             -> E.throwIO   MustNotReached

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
        recvResult <- recvCryptoData conn
        case recvResult of
            Left err -> return $ Left err
            Right (actual, bs)
                | actual /= expected -> failure $
                    "encryption level mismatch: expected " ++ show expected ++
                    " but got " ++ show actual
                | otherwise -> do
                    n <- recvCompleted hsr
                    case expected of
                        InitialLevel | isServer conn ->
                            -- To prevent CI0'
                            when (n > 0) $
                                sendCryptoData conn $ OutControl InitialLevel []
                        HandshakeLevel | isClient conn ->
                            -- Sending ACKs for three times rule
                            when ((n `mod` 3) == 1) $
                                sendCryptoData conn $ OutControl HandshakeLevel []
                        _ -> return ()
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
    mytid <- myThreadId
    tid <- forkIO (handshaker `E.catch` tell mytid)
    setKillHandshaker conn tid
    if use0RTT then
       wait0RTTReady conn
     else
       wait1RTTReady conn
  where
    tell tid e = notifyPeer conn (getErrorCause e) >>= E.throwTo tid
    installKeysClient _ (InstallEarlyKeys mEarlySecInf) = do
        setEarlySecretInfo conn mEarlySecInf
        setHeaderProtectionKey conn RTT0Level
        setConnection0RTTReady conn
    installKeysClient hsr (InstallHandshakeKeys hndSecInf) = do
        setHandshakeSecretInfo conn hndSecInf
        setHeaderProtectionKey conn HandshakeLevel
        setEncryptionLevel conn HandshakeLevel
        rxLevelChanged hsr
    installKeysClient hsr (InstallApplicationKeys appSecInf) = do
        setApplicationSecretInfo conn appSecInf
        setHeaderProtectionKey conn RTT1Level
        setEncryptionLevel conn RTT1Level
        rxLevelChanged hsr
        setConnection1RTTReady conn
        cidInfo <- getNewMyCID conn
        let ncid = NewConnectionID cidInfo 0
        putOutput conn $ OutControl RTT1Level [ncid]
    done ctx = do
        TLS.getNegotiatedProtocol ctx >>= setApplicationProtocol conn
        minfo <- TLS.contextGetInformation ctx
        forM_ (minfo >>= TLS.infoTLS13HandshakeMode) $ \mode ->
            setTLSMode conn mode
        info <- getConnectionInfo conn
        connDebugLog conn $ show info

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
    mytid <- myThreadId
    tid <- forkIO (handshaker `E.catch` tell mytid)
    setKillHandshaker conn tid
    wait1RTTReady conn
  where
    tell tid e = notifyPeer conn (getErrorCause e) >>= E.throwTo tid
    installKeysServer _ (InstallEarlyKeys mEarlySecInf) = do
        setEarlySecretInfo conn mEarlySecInf
        setHeaderProtectionKey conn RTT0Level
    installKeysServer hsr (InstallHandshakeKeys hndSecInf) = do
        setHandshakeSecretInfo conn hndSecInf
        setHeaderProtectionKey conn HandshakeLevel
        setEncryptionLevel conn HandshakeLevel
        rxLevelChanged hsr
    installKeysServer _ (InstallApplicationKeys appSecInf) = do
        setApplicationSecretInfo conn appSecInf
        setHeaderProtectionKey conn RTT1Level
        -- will switch to RTT1Level after client Finished
        -- is received and verified
    done ctx = do
        TLS.getNegotiatedProtocol ctx >>= setApplicationProtocol conn
        minfo <- TLS.contextGetInformation ctx
        forM_ (minfo >>= TLS.infoTLS13HandshakeMode) $ \mode ->
            setTLSMode conn mode
        TLS.getClientCertificateChain ctx >>= setCertificateChain conn
        clearKillHandshaker conn
        setEncryptionLevel conn RTT1Level
        fire 2000000 $ dropSecrets conn
        putOutput conn $ OutControl RTT1Level [HandshakeDone]
        setConnectionEstablished conn
        --
        info <- getConnectionInfo conn
        connDebugLog conn $ show info

setPeerParams :: Connection -> [ExtensionRaw] -> IO ()
setPeerParams conn [ExtensionRaw extid bs]
  | extid == extensionID_QuicTransportParameters = do
        let mparams = decodeParameters bs
        case mparams of
          Nothing    -> err
          Just params -> do
              checkAuthCIDs params
              setParams params
  where
    err = E.throwIO TransportParameterError
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
    setParams params = do
        setPeerParameters conn params
        when (isClient conn) $ do
            case statelessResetToken params of
              Nothing  -> return ()
              Just srt -> setPeerStatelessResetToken conn srt
        setTxMaxData conn $ initialMaxData params
setPeerParams _ _ = return ()

getErrorCause :: TLS.TLSException -> TLS.TLSError
getErrorCause (TLS.HandshakeFailed e) = e
getErrorCause (TLS.Terminated _ _ e) = e
getErrorCause e =
    let msg = "unexpected TLS exception: " ++ show e
     in TLS.Error_Protocol (msg, True, TLS.InternalError)

notifyPeer :: Connection -> TLS.TLSError -> IO QUICError
notifyPeer conn err = do
    let ad = errorToAlertDescription err
        frames = [ConnectionCloseQUIC (CryptoError ad) 0 ""]
    level <- getEncryptionLevel conn
    putOutput conn $ OutControl level frames
    setCloseSent conn
    return $ HandshakeFailed $ errorToAlertMessage err

notifyPeerAsync :: Connection -> TLS.TLSError -> IO QUICError
notifyPeerAsync conn err = do
    exception <- notifyPeer conn err
    putInput conn $ InpError exception  -- also report in next recvStream
    return exception
