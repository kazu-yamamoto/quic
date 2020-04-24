{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

import qualified Control.Exception as E
import Data.ByteString
import Data.IORef
import qualified Network.TLS as TLS
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
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
      -- When QUICError values have no TLS counterpart: we throw them as is.
      -- TLS will transform into TLS.Error_Misc, this is quite unfortunate.
      InpVersion (Just ver)      -> E.throwIO $ NextVersion ver
      InpVersion Nothing         -> E.throwIO   VersionNegotiationFailed
      InpError e                 -> E.throwIO e
      InpApplicationError err bs -> E.throwIO $ ApplicationErrorOccurs err bs
      InpStream{}                -> E.throwIO   MustNotReached

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
                            when ((n `mod` 3) == 0) $
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

handshakeClient :: ClientConfig -> Connection -> IO ()
handshakeClient conf conn = do
    ver <- getVersion conn
    hsr <- newHndStateRef
    let sendEarlyData = isJust $ ccEarlyData conf
        qc = QUICCallbacks { quicSend = sendTLS conn hsr
                           , quicRecv = recvTLS conn hsr
                           , quicInstallKeys = installKeysClient
                           , quicNotifyExtensions = setPeerParams conn
                           }
    control <- clientController qc conf ver (setResumptionSession conn) sendEarlyData
    setClientController conn control
    state <- control GetClientHello
    case state of
        SendClientFinished -> return ()
        ClientHandshakeFailed e -> notifyPeer conn e >>= E.throwIO
        _ -> E.throwIO $ HandshakeFailed $ "handshakeClient: unexpected " ++ show state

  where
    installKeysClient (InstallEarlyKeys mEarlySecInf) = do
        setEarlySecretInfo conn mEarlySecInf
        sendCryptoData conn $ OutEarlyData (ccEarlyData conf)
    installKeysClient (InstallHandshakeKeys hndSecInf) = do
        setHandshakeSecretInfo conn hndSecInf
        setEncryptionLevel conn HandshakeLevel
    installKeysClient (InstallApplicationKeys appSecInf) = do
        setApplicationSecretInfo conn appSecInf
        setEncryptionLevel conn RTT1Level

-- second half the the TLS handshake, executed out of the main thread
handshakeClientAsync :: Connection -> ClientController -> IO ()
handshakeClientAsync conn control = handleLog logAction $ do
    -- RecvSessionTicket or ClientHandshakeDone
    state <- control PutSessionTicket
    case state of
        RecvSessionTicket -> return ()
        ClientHandshakeFailed e -> notifyPeerAsync conn e >>= E.throwIO
        _ -> E.throwIO $ HandshakeFailed $ "unexpected " ++ show state
  where
    logAction msg = connDebugLog conn ("client handshake: " ++ msg)

----------------------------------------------------------------

handshakeServer :: ServerConfig -> OrigCID -> Connection -> IO ()
handshakeServer conf origCID conn = do
    ver <- getVersion conn
    hsr <- newHndStateRef
    let qc = QUICCallbacks { quicSend = sendTLS conn hsr
                           , quicRecv = recvTLS conn hsr
                           , quicInstallKeys = installKeysServer
                           , quicNotifyExtensions = setPeerParams conn
                           }
    control <- serverController qc conf ver origCID
    setServerController conn control
    state <- control PutClientHello
    case state of
        SendServerFinished -> return ()
        ServerHandshakeFailed e -> notifyPeer conn e >>= E.throwIO
        _ -> E.throwIO $ HandshakeFailed $ "handshakeServer: unexpected " ++ show state

  where
    installKeysServer (InstallEarlyKeys mEarlySecInf) =
        setEarlySecretInfo conn mEarlySecInf
    installKeysServer (InstallHandshakeKeys hndSecInf) = do
        setHandshakeSecretInfo conn hndSecInf
        setEncryptionLevel conn HandshakeLevel
    installKeysServer (InstallApplicationKeys appSecInf) =
        setApplicationSecretInfo conn appSecInf
        -- will switch to RTT1Level after client Finished
        -- is received and verified

-- second half the the TLS handshake, executed out of the main thread
handshakeServerAsync :: Connection -> ServerController -> IO ()
handshakeServerAsync conn control = handleLog logAction $ do
    state <- control PutClientFinished
    case state of
      SendSessionTicket -> do
          setEncryptionLevel conn RTT1Level
          -- aka sendCryptoData
          ServerHandshakeDone <- control ExitServer
          clearServerController conn
          --
          setConnectionEstablished conn
          fire 2000000 $ dropSecrets conn
          --
          cryptoToken <- generateToken =<< getVersion conn
          mgr <- getTokenManager conn
          token <- encryptToken mgr cryptoToken
          cidInfo <- getNewMyCID conn
          register <- getRegister conn
          register (cidInfoCID cidInfo) conn
          let ncid = NewConnectionID cidInfo 0
          let frames = [HandshakeDone,NewToken token,ncid]
          putOutput conn $ OutControl RTT1Level frames
      ServerHandshakeFailed e -> notifyPeerAsync conn e >>= E.throwIO
      _ -> E.throwIO $ HandshakeFailed $ "unexpected " ++ show state
  where
    logAction msg = connDebugLog conn ("server handshake: " ++ msg)

setPeerParams :: Connection -> [ExtensionRaw] -> IO ()
setPeerParams conn [ExtensionRaw extid params]
  | extid == extensionID_QuicTransportParameters = do
        let mplist = decodeParametersList params
        case mplist of
          Nothing    -> connDebugLog conn "cannot decode parameters"
          Just plist -> setPeerParameters conn plist
setPeerParams _ _ = return ()

notifyPeer :: Connection -> TLS.TLSError -> IO QUICError
notifyPeer conn err = do
    let ad = errorToAlertDescription err
        frames = [ConnectionCloseQUIC (CryptoError ad) 0 ""]
    level <- getEncryptionLevel conn
    putOutput conn $ OutControl level frames
    return $ HandshakeFailed $ errorToAlertMessage err

notifyPeerAsync :: Connection -> TLS.TLSError -> IO QUICError
notifyPeerAsync conn err = do
    exception <- notifyPeer conn err
    putInput conn $ InpError exception  -- also report in next recvStream
    return exception
