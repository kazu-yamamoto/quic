{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Handshake where

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
sendCryptoData = putOutput

recvCryptoData :: Connection -> IO (EncryptionLevel, ByteString, Offset)
recvCryptoData conn = do
    dat <- takeCrypto conn
    case dat of
      InpHandshake lvl bs off _  -> return (lvl, bs, off)
      InpVersion (Just ver)      -> E.throwIO $ NextVersion ver
      InpVersion Nothing         -> E.throwIO   VersionNegotiationFailed
      InpError e                 -> E.throwIO e
      InpTransportError err _ bs -> E.throwIO $ TransportErrorOccurs err bs
      InpApplicationError err bs -> E.throwIO $ ApplicationErrorOccurs err bs
      InpStream{}                -> E.throwIO   MustNotReached
      InpFin{}                   -> E.throwIO   MustNotReached

----------------------------------------------------------------

handshakeClient :: ClientConfig -> Connection -> IO ()
handshakeClient conf conn = do
    ver <- getVersion conn
    let sendEarlyData = isJust $ ccEarlyData conf
    control <- clientController conf ver (setResumptionSession conn) sendEarlyData
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
              setPeerParams conn exts
              sendCryptoData conn $ OutHndClientFinished cf
          _ -> E.throwIO $ HandshakeFailed "putServerFinished"

----------------------------------------------------------------

handshakeServer :: ServerConfig -> OrigCID -> Connection -> IO ()
handshakeServer conf origCID conn = do
    ver <- getVersion conn
    control <- serverController conf ver origCID
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
        -- Suppose that client Initial are fragmented, say, CI0 and CI1.
        -- A socket for CI0 is connected to peer's address/port.
        -- CI1 goes to another connection and is rejected because
        -- socket for CI1 cannot be connected.
        -- CI0 and CI1 would be resent by the client.
        -- So, CI0' should be filtered out.
        if expectedOff /= off then
            loop expectedOff
          else do
            state <- control $ PutClientHello ch
            let expectedOff' = expectedOff + B.length ch
            case state of
              SendRequestRetry hrr -> do
                  sendCryptoData conn $ OutHndServerHelloR hrr
                  loop expectedOff'
              SendServerHello sh0 exts mEarlySecInf hndSecInf -> do
                  setEarlySecretInfo conn mEarlySecInf
                  setHandshakeSecretInfo conn hndSecInf
                  setEncryptionLevel conn HandshakeLevel
                  setPeerParams conn exts
                  return sh0
              ServerNeedsMore -> do
                  -- yield
                  -- To prevent CI0' above.
                  sendCryptoData conn $ OutControl InitialLevel []
                  loop expectedOff'
              _ -> E.throwIO $ HandshakeFailed "recvClientHello"

setPeerParams :: Connection -> [ExtensionRaw] -> IO ()
setPeerParams conn [ExtensionRaw 0xffa5 params] = do
    let Just plist = decodeParametersList params
    setPeerParameters conn plist
setPeerParams _ _ = return ()
