{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver (
    receiver
  ) where

import Control.Concurrent
import Network.TLS.QUIC hiding (RTT0)

import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Timeout
import Network.QUIC.Types

receiver :: Connection -> Receive -> IO ()
receiver conn recv = handleLog logAction $ do
    loopHandshake
    loopEstablished
  where
    loopHandshake = do
        CryptPacket hdr crypt <- recv
        processCryptPacketHandshake conn hdr crypt
        established <- isConnectionEstablished conn
        unless established loopHandshake
    loopEstablished = forever $ do
        CryptPacket hdr crypt <- recv
        let cid = headerMyCID hdr
        included <- myCIDsInclude conn cid
        if included then do
            used <- isMyCID conn cid
            unless used $ setMyCID conn cid
            processCryptPacket conn hdr crypt
          else do
            qlogDropped conn hdr
            connDebugLog conn "CID is unknown"
    logAction msg = connDebugLog conn ("receiver: " ++ msg)

processCryptPacketHandshake :: Connection -> Header -> Crypt -> IO ()
processCryptPacketHandshake conn hdr crypt = do
    let level = packetEncryptionLevel hdr
    -- If RTT1 comes between Initial and Handshake,
    -- checkEncryptionLevel waits forever. To avoid this, timeout
    -- used. If timeout happens, the packet cannot be decrypted and
    -- thrown away.
    mt <- timeout 100000 $ checkEncryptionLevel conn level
    if isNothing mt then do
        if isCryptDelayed crypt then do
            qlogDropped conn hdr
            connDebugLog conn "Timeout: ignoring a packet"
          else do
            (_, q) <- getSockInfo conn
            writeRecvQ q $ CryptPacket hdr $ setCryptDelayed crypt
      else do
        peercid <- getPeerCID conn
        when (isClient conn
           && level == HandshakeLevel
           && peercid /= headerPeerCID hdr) $ do
            resetPeerCID conn $ headerPeerCID hdr
        processCryptPacket conn hdr crypt

processCryptPacket :: Connection -> Header -> Crypt -> IO ()
processCryptPacket conn hdr crypt = do
    let level = packetEncryptionLevel hdr
    mplain <- decryptCrypt conn crypt level
    case mplain of
      Just plain@(Plain _ pn frames) -> do
          -- For Ping, record PPN first, then send an ACK.
          -- fixme: need to check Sec 13.1
          when (any ackEliciting frames) $
              addPeerPacketNumbers conn level pn
          unless (isCryptLogged crypt) $
              qlogReceived conn $ PlainPacket hdr plain
          mapM_ (processFrame conn level) frames
      Nothing -> do
          statelessReset <- isStateessReset conn hdr crypt
          if statelessReset then do
              qlogReceived conn StatelessReset
              connDebugLog conn "Connection is reset statelessly"
              setCloseReceived conn
              clearThreads conn
            else do
              qlogDropped conn hdr
              connDebugLog conn $ "Cannot decrypt: " ++ show level
              -- fixme: sending statelss reset

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
              putInputCrypto conn lvl off cdat
              getServerController conn >>= sendSessionTicket conn
      RTT1Level
        | isClient conn -> do
              putInputCrypto conn lvl off cdat
              getClientController conn >>= recvSessionTicket conn
        | otherwise -> do
              connDebugLog conn "processFrame: Short:Crypto for server"
processFrame conn _ (NewToken token) = do
    setNewToken conn token
    connDebugLog conn "processFrame: NewToken"
processFrame conn _ (NewConnectionID cidInfo rpt) = do
    addPeerCID conn cidInfo
    when (rpt >= 1) $ do
        seqNums <- setPeerCIDAndRetireCIDs conn rpt
        let frames = map RetireConnectionID seqNums
        putOutput conn $ OutControl RTT1Level frames
processFrame conn _ (RetireConnectionID sn) = do
    mcidInfo <- retireMyCID conn sn
    when (isServer conn) $ case mcidInfo of
      Nothing -> return ()
      Just (CIDInfo _ cid _) -> do
          unregister <- getUnregister conn
          unregister cid
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
processFrame conn RTT1Level (Stream sid off dat fin)
  | isClient conn = putInputStream conn sid off dat fin
  | otherwise     = do
        established <- isConnectionEstablished conn
        if established then
            putInputStream conn sid off dat fin
          else void . forkIO $ do
            -- Client Finish and Stream are somtime out-ordered.
            -- This causes a race condition between transport and app.
            mx <- timeout 100000 $ waitEstablished conn
            case mx of
              Nothing -> return ()
              Just _  -> putInputStream conn sid off dat fin
processFrame conn lvl Ping = do
    -- An implementation sends:
    --   Handshake PN=2
    --   Handshake PN=3 Ping
    --   Handshake PN=0
    --   Handshake PN=1
    -- If ACK 2-3 sends immediately, the peer misunderstand that
    -- 0 and 1 are dropped.
    when (lvl == RTT1Level) $ putOutput conn $ OutControl lvl []
processFrame conn _ HandshakeDone = do
    setConnectionEstablished conn
    fire 2000000 $ do
        control <- getClientController conn
        ClientHandshakeDone <- control ExitClient
        clearClientController conn
        dropSecrets conn
processFrame conn _ _frame        = do
    connDebugLog conn $ "processFrame: " ++ show _frame

sendSessionTicket :: Connection -> ServerController -> IO ()
sendSessionTicket conn control = do
    res <- control PutClientFinished
    case res of
      SendSessionTicket -> do
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
      _ -> return ()

recvSessionTicket :: Connection -> ClientController -> IO ()
recvSessionTicket _conn control =
    -- RecvSessionTicket or ClientHandshakeDone
    void $ control PutSessionTicket

-- QUIC version 1 uses only short packets for stateless reset.
-- But we should check other packets, too.
isStateessReset :: Connection -> Header -> Crypt -> IO Bool
isStateessReset conn header Crypt{..} = do
    ok <- myCIDsInclude conn $ headerMyCID header
    if ok then
        return False
      else case decodeStatelessResetToken cryptPacket of
             Nothing    -> return False
             Just token -> isStatelessRestTokenValid conn token
