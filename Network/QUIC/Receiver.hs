{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver (
    receiver
  ) where

import qualified Control.Exception as E

import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Timeout
import Network.QUIC.Types

receiver :: Connection -> Receive -> IO ()
receiver conn recv = handleLog logAction $ do
    loopHandshake
    loopEstablished
  where
    recvTimeout = do
        -- The spec says that CC is not sent when timeout.
        -- But we intentionally sends CC when timeout.
        -- fixme: 30 sec comes from Warp
        mx <- timeout 30000000 recv
        case mx of
          Nothing -> do
              putInput conn $ InpError ConnectionIsTimeout
              E.throwIO Break
          Just x  -> return x
    loopHandshake = do
        cpkt <- recvTimeout
        processCryptPacketHandshake conn cpkt
        established <- isConnectionEstablished conn
        unless established loopHandshake
    loopEstablished = forever $ do
        CryptPacket hdr crypt <- recvTimeout
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

processCryptPacketHandshake :: Connection -> CryptPacket -> IO ()
processCryptPacketHandshake conn cpkt@(CryptPacket hdr crypt) = do
    let level = packetEncryptionLevel hdr
    decryptable <- checkEncryptionLevel conn level cpkt
    when decryptable $ do
        when (isClient conn && level == InitialLevel) $ do
            peercid <- getPeerCID conn
            let newPeerCID = headerPeerCID hdr
            when (peercid /= headerPeerCID hdr) $ resetPeerCID conn newPeerCID
            setPeerAuthCIDs conn $ \auth -> auth { initSrcCID = Just newPeerCID }
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
              putInput conn $ InpError ConnectionIsReset
            else do
              qlogDropped conn hdr
              connDebugLog conn $ "Cannot decrypt: " ++ show level
              -- fixme: sending statelss reset

processFrame :: Connection -> EncryptionLevel -> Frame -> IO ()
processFrame _ _ Padding{} = return ()
processFrame conn lvl Ping = do
    -- An implementation sends:
    --   Handshake PN=2
    --   Handshake PN=3 Ping
    --   Handshake PN=0
    --   Handshake PN=1
    -- If ACK 2-3 sends immediately, the peer misunderstand that
    -- 0 and 1 are dropped.
    when (lvl == RTT1Level) $ putOutput conn $ OutControl lvl []
processFrame conn _ (Ack ackInfo _) = do
    let pns = fromAckInfo ackInfo
    mapM_ (releasePlainPacketRemoveAcks conn) pns
processFrame _ _ ResetStream{} = return ()
processFrame _ _ StopSending{} = return ()
processFrame conn lvl (Crypto off cdat) = do
    case lvl of
      InitialLevel   -> do
          putInputCrypto conn lvl off cdat
      RTT0Level -> do
          connDebugLog conn $ "processFrame: invalid packet type " ++ show lvl
      HandshakeLevel ->
          putInputCrypto conn lvl off cdat
      RTT1Level
        | isClient conn ->
              putInputCrypto conn lvl off cdat
        | otherwise -> do
              connDebugLog conn "processFrame: Short:Crypto for server"
processFrame conn _ (NewToken token) = do
    setNewToken conn token
    connDebugLog conn "processFrame: NewToken"
processFrame conn RTT0Level (StreamF sid off (dat:_) fin) =
    putInputStream conn sid off dat fin
processFrame conn RTT1Level (StreamF sid off (dat:_) fin) =
    putInputStream conn sid off dat fin
processFrame _ _ MaxData{} = return ()
processFrame _ _ MaxStreamData{} = return ()
processFrame _ _ MaxStreams{} = return ()
processFrame _ _ DataBlocked{} = return ()
processFrame _ _ StreamDataBlocked{} = return ()
processFrame _ _ StreamsBlocked{} = return ()
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
processFrame conn lvl (ConnectionCloseQUIC err ftyp reason) = do
    when (lvl `elem` [InitialLevel, HandshakeLevel]) $
        putCrypto conn $ InpTransportError err ftyp reason
    putInput conn $ InpTransportError err ftyp reason
    setCloseReceived conn
processFrame conn _ (ConnectionCloseApp err reason) = do
    putInput conn $ InpApplicationError err reason
    setCloseReceived conn
processFrame conn _ HandshakeDone = do
    setConnectionEstablished conn
    fire 2000000 $ do
        killHandshaker conn
        dropSecrets conn
processFrame conn _ (UnknownFrame _n)       = do
    connDebugLog conn $ "processFrame: " ++ show _n
processFrame _ _ _ = return () -- error

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
