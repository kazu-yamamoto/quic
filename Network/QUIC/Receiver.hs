{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver (
    receiver
  ) where

import qualified Control.Exception as E
import qualified Data.ByteString as BS

import Network.QUIC.Connection
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Stream
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
        mx <- timeout (idleTimeout * 1000) recv -- fixme: taking minimum with peer's one
        case mx of
          Nothing -> do
              exitConnection conn ConnectionIsTimeout
              E.throwIO ConnectionIsTimeout -- fixme
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
          addPeerPacketNumbers conn level pn
          when (level == RTT1Level) $ setPeerPacketNumber conn pn
          unless (isCryptLogged crypt) $
              qlogReceived conn $ PlainPacket hdr plain
          mapM_ (processFrame conn level) frames
          when (any ackEliciting frames && level == RTT1Level) $ do
              if all shouldDelay frames then do
                  sendAck <- checkDelayedAck conn
                  when sendAck $ putOutput conn $ OutControl level []
                else do
                  putOutput conn $ OutControl level []
                  resetDelayedAck conn
      Nothing -> do
          statelessReset <- isStateessReset conn hdr crypt
          if statelessReset then do
              qlogReceived conn StatelessReset
              connDebugLog conn "Connection is reset statelessly"
              setCloseReceived conn
              E.throwTo (connThreadId conn) ConnectionIsReset
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
    when (lvl == RTT1Level) $ do
        putOutput conn $ OutControl lvl []
        resetDelayedAck conn
processFrame conn _ (Ack ackInfo _) =
    releaseByAcks conn ackInfo
processFrame _ _ ResetStream{} = return ()
processFrame _ _ StopSending{} = return ()
processFrame conn lvl (Crypto off cdat) = do
    let len = BS.length cdat
        rx = RxStreamData cdat off len False
    case lvl of
      InitialLevel   -> do
          putRxCrypto conn lvl rx
      RTT0Level -> do
          connDebugLog conn $ "processFrame: invalid packet type " ++ show lvl
      HandshakeLevel ->
          putRxCrypto conn lvl rx
      RTT1Level
        | isClient conn ->
              putRxCrypto conn lvl rx
        | otherwise -> do
              connDebugLog conn "processFrame: Short:Crypto for server"
processFrame conn _ (NewToken token) =
    setNewToken conn token
processFrame conn RTT0Level (StreamF sid off (dat:_) fin) = do
    strm <- getStream conn sid
    let len = BS.length dat
        rx = RxStreamData dat off len fin
    putRxStreamData strm rx
    addRxData conn $ BS.length dat             -- fixme: including 0RTT?
processFrame conn RTT1Level (StreamF sid off (dat:_) fin) = do
    strm <- getStream conn sid
    let len = BS.length dat
        rx = RxStreamData dat off len fin
    putRxStreamData strm rx
    addRxStreamData strm $ BS.length dat
    window <- getRxStreamWindow strm
    let initialWindow = initialRxMaxStreamData conn sid
    when (window <= (initialWindow `div` 2)) $ do
        newMax <- addRxMaxStreamData strm initialWindow
        putOutput conn $ OutControl RTT1Level [MaxStreamData sid newMax]
        resetDelayedAck conn
    addRxData conn $ BS.length dat
    cwindow <- getRxDataWindow conn
    let cinitialWindow = initialMaxData $ getMyParameters conn
    when (cwindow <= (cinitialWindow `div` 2)) $ do
        newMax <- addRxMaxData conn cinitialWindow
        putOutput conn $ OutControl RTT1Level [MaxData newMax]
        resetDelayedAck conn
    when fin $ do
        putOutput conn $ OutControl RTT1Level []
        resetDelayedAck conn
processFrame conn _ (MaxData n) =
    setTxMaxData conn n
processFrame conn _ (MaxStreamData sid n) = do
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> return ()
      Just strm -> setTxMaxStreamData strm n
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
        resetDelayedAck conn
processFrame conn _ (RetireConnectionID sn) = do
    mcidInfo <- retireMyCID conn sn
    when (isServer conn) $ case mcidInfo of
      Nothing -> return ()
      Just (CIDInfo _ cid _) -> do
          unregister <- getUnregister conn
          unregister cid
processFrame conn RTT1Level (PathChallenge dat) = do
    putOutput conn $ OutControl RTT1Level [PathResponse dat]
    resetDelayedAck conn
processFrame conn RTT1Level (PathResponse dat) =
    checkResponse conn dat
processFrame conn _ (ConnectionCloseQUIC err _ftyp reason) = do
    setCloseReceived conn
    if err == NoError then do
        sent <- isCloseSent conn
        unless sent $ exitConnection conn ConnectionIsClosed
      else do
        exitConnection conn $ TransportErrorOccurs err reason
processFrame conn _ (ConnectionCloseApp err reason) = do
    setCloseReceived conn
    exitConnection conn $ ApplicationErrorOccurs err reason
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

putRxCrypto :: Connection -> EncryptionLevel -> RxStreamData -> IO ()
putRxCrypto conn lvl rx = do
    strm <- getCryptoStream conn lvl
    dats <- fst <$> tryReassemble strm rx
    mapM_ (putCrypto conn . CryptoD lvl) dats
