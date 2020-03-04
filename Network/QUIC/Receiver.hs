{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver (
    receiver
  ) where

import Control.Concurrent
import Network.TLS.QUIC
import System.Timeout

import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Qlog
import Network.QUIC.Types

receiver :: Connection -> Receive -> IO ()
receiver conn recv = handleLog logAction $ forever
    (recv >>= processCryptPacket conn)
  where
    logAction msg = connDebugLog conn ("receiver: " ++ msg)

processCryptPacket :: Connection -> CryptPacket -> IO ()
processCryptPacket conn (CryptPacket header crypt) = do
    let level = packetEncryptionLevel header
    -- If RTT1 comes just after Initial, checkEncryptionLevel
    -- waits forever. To avoid this, timeout used.
    -- If timeout happens, the packet cannot be decrypted
    -- and thrown away.
    mt <- timeout 100000 $ checkEncryptionLevel conn level
    if isNothing mt then
        connDebugLog conn "Timeout: ignoring a packet"
      else do
        when (isClient conn && level == HandshakeLevel) $
            resetPeerCID conn $ headerPeerCID header
        mplain <- decryptCrypt conn crypt level
        case mplain of
          Just plain@(Plain _ pn fs) -> do
              -- For Ping, record PPN first, then send an ACK.
              -- fixme: need to check Sec 13.1
              addPeerPacketNumbers conn level pn
              unless (cryptLogged crypt) $
                  qlogReceived conn $ PlainPacket header plain
              mapM_ (processFrame conn level) fs
          Nothing -> do
              statelessReset <- isStateessReset conn header crypt
              if statelessReset then do
                  connDebugLog conn "Connection is reset statelessly"
                  setCloseReceived conn
                  clearThreads conn
                else do
                  connDebugLog conn $ "Cannot decrypt: " ++ show level
                  return () -- fixme: sending statelss reset

processFrame :: Connection -> EncryptionLevel -> Frame -> IO ()
processFrame _ _ Padding{} = return ()
processFrame conn _ (Ack ackInfo _) = do
    let pns = fromAckInfo ackInfo
    mapM_ (releasePlainPacketRemoveAcks conn) pns
processFrame conn lvl (Crypto off cdat) = do
    case lvl of
      InitialLevel   -> do
          putInputCrypto conn lvl off cdat
      RTT0Level -> do
          connDebugLog conn $ "processFrame: invalid packet type " ++ show lvl
      HandshakeLevel
        | isClient conn -> do
              putInputCrypto conn lvl off cdat
        | otherwise -> do
              control <- getServerController conn
              res <- control $ PutClientFinished cdat
              case res of
                SendSessionTicket nst -> do
                    -- aka sendCryptoData
                    putOutput conn $ OutHndServerNST nst
                    ServerHandshakeDone <- control ExitServer
                    clearServerController conn
                    cryptoToken <- generateToken =<< getVersion conn
                    mgr <- getTokenManager conn
                    token <- encryptToken mgr cryptoToken
                    (sn,mycid,srt) <- getNewMyCID conn
                    register <- getRegister conn
                    register mycid conn
                    let ncid = NewConnectionID sn 0 mycid srt
                    let frames = [HandshakeDone,NewToken token,ncid]
                    putOutput conn $ OutControl RTT1Level frames
                _ -> return ()
      RTT1Level
        | isClient conn -> do
              control <- getClientController conn
              -- RecvSessionTicket or ClientHandshakeDone
              void $ control $ PutSessionTicket cdat
        | otherwise -> do
              connDebugLog conn "processFrame: Short:Crypto for server"
processFrame conn _ (NewToken token) = do
    setNewToken conn token
    connDebugLog conn "processFrame: NewToken"
processFrame conn _ (NewConnectionID sn _ peercid srt) = do
    -- fixme: retire to
    addPeerCID conn (sn, peercid, srt)
processFrame conn _ (RetireConnectionID sn) =
    retireMyCID conn sn
processFrame conn RTT1Level (PathChallenge dat) =
    putOutput conn $ OutControl RTT1Level [PathResponse dat]
processFrame conn RTT1Level (PathResponse dat) =
    checkResponse conn dat
processFrame conn _ (ConnectionCloseQUIC err ftyp reason) = do
    putInput conn $ InpTransportError err ftyp reason
    -- to cancel handshake
    putCrypto conn $ InpTransportError err ftyp reason
    setCloseSent conn
    setCloseReceived conn
    clearThreads conn
processFrame conn _ (ConnectionCloseApp err reason) = do
    connDebugLog conn $ "processFrame: ConnectionCloseApp " ++ show err
    putInput conn $ InpApplicationError err reason
    -- to cancel handshake
    putCrypto conn $ InpApplicationError err reason
    setCloseSent conn
    setCloseReceived conn
    clearThreads conn
processFrame conn RTT0Level (Stream sid off dat fin) = do
    putInputStream conn sid off dat fin
processFrame conn RTT1Level (Stream sid off dat fin) =
    putInputStream conn sid off dat fin
processFrame conn lvl Ping = do
    putOutput conn $ OutControl lvl []
processFrame conn _ HandshakeDone = do
    control <- getClientController conn
    void $ forkIO $ do
        threadDelay 2000000
        ClientHandshakeDone <- control ExitClient
        clearClientController conn
processFrame conn _ _frame        = do
    connDebugLog conn $ "processFrame: " ++ show _frame

-- QUIC version 1 uses only short packets for stateless reset.
-- But we should check other packets, too.
isStateessReset :: Connection -> Header -> Crypt -> IO Bool
isStateessReset conn header Crypt{..} = do
    myCID <- getMyCID conn
    if myCID == headerMyCID header then
        return False
      else case decodeStatelessResetToken cryptPacket of
             Nothing    -> return False
             Just token -> isStatelessRestTokenValid conn token
