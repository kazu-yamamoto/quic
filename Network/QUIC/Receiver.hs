{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver (
    receiver
  ) where

import qualified Control.Exception as E
import qualified Data.ByteString as BS
import Network.TLS (AlertDescription(..))

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Recovery
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
        ito <- readMinIdleTimeout conn
        mx <- timeout ito recv -- fixme: taking minimum with peer's one
        case mx of
          Nothing -> do
              exitConnection conn ConnectionIsTimeout
              E.throwIO ConnectionIsTimeout -- fixme
          Just x  -> return x
    loopHandshake = do
        rpkt <- recvTimeout
        processReceivedPacketHandshake conn rpkt
        established <- isConnectionEstablished conn
        unless established loopHandshake
    loopEstablished = forever $ do
        rpkt <- recvTimeout
        let CryptPacket hdr _ = rpCryptPacket rpkt
            cid = headerMyCID hdr
        included <- myCIDsInclude conn cid
        if included then do
            used <- isMyCID conn cid
            unless used $ setMyCID conn cid
            processReceivedPacket conn rpkt
          else do
            qlogDropped conn hdr
            connDebugLog conn $ bhow cid <> " is unknown"
    logAction msg = connDebugLog conn ("receiver: " <> msg)

processReceivedPacketHandshake :: Connection -> ReceivedPacket -> IO ()
processReceivedPacketHandshake conn rpkt = do
    let CryptPacket hdr _ = rpCryptPacket rpkt
        lvl = rpEncryptionLevel rpkt
    mx <- timeout (Microseconds 10000) $ waitEncryptionLevel conn lvl
    case mx of
      Nothing -> do
          putOffCrypto conn lvl rpkt
          when (isClient conn) $ do
              lvl' <- getEncryptionLevel conn
              speedup (connLDCC conn) lvl' "not decryptable"
      Just ()
        | isClient conn -> do
              when (lvl == InitialLevel) $ do
                  peercid <- getPeerCID conn
                  let newPeerCID = headerPeerCID hdr
                  when (peercid /= headerPeerCID hdr) $
                      resetPeerCID conn newPeerCID
                  setPeerAuthCIDs conn $ \auth ->
                      auth { initSrcCID = Just newPeerCID }
              processReceivedPacket conn rpkt
        | otherwise -> do
              mycid <- getMyCID conn
              when (lvl == HandshakeLevel
                    || (lvl == InitialLevel && mycid == headerMyCID hdr)) $ do
                  setAddressValidated conn
              when (lvl == HandshakeLevel) $ do
                  discarded <- getPacketNumberSpaceDiscarded (connLDCC conn) InitialLevel
                  unless discarded $ do
                      dropSecrets conn InitialLevel
                      clearCryptoStream conn InitialLevel
                      onPacketNumberSpaceDiscarded (connLDCC conn) InitialLevel
              processReceivedPacket conn rpkt

processReceivedPacket :: Connection -> ReceivedPacket -> IO ()
processReceivedPacket conn rpkt = do
    let CryptPacket hdr crypt = rpCryptPacket rpkt
        lvl = rpEncryptionLevel rpkt
        tim = rpTimeRecevied rpkt
    mplain <- decryptCrypt conn crypt lvl
    case mplain of
      Just plain@Plain{..} -> do
          when (isIllegalReservedBits plainMarks || isNoFrames plainMarks) $
              sendCCandExitConnection conn ProtocolViolation "Non 0 RR bits or no frames" 0
          when (isUnknownFrame plainMarks) $
              sendCCandExitConnection conn FrameEncodingError "Unknown frame" 0
          -- For Ping, record PPN first, then send an ACK.
          onPacketReceived (connLDCC conn) lvl plainPacketNumber
          when (lvl == RTT1Level) $ setPeerPacketNumber conn plainPacketNumber
          unless (isCryptLogged crypt) $
              qlogReceived conn (PlainPacket hdr plain) tim
          ver <- getVersion conn
          let ackEli   = any ackEliciting   plainFrames
              shouldDrop = ver >= Draft32
                        && rpReceivedBytes rpkt < defaultQUICPacketSize
                        && (lvl == InitialLevel && ackEli)
          if shouldDrop then do
              stdoutLogger ("Drop packet whose size is " <> bhow (rpReceivedBytes rpkt))
              qlogDropped conn hdr
            else do
              mapM_ (processFrame conn lvl) plainFrames
              when ackEli $ do
                  case lvl of
                    RTT0Level -> return ()
                    RTT1Level -> delayedAck conn
                    _         -> do
                        sup <- getSpeedingUp (connLDCC conn)
                        when sup $ do
                            qlogDebug conn $ Debug "ping for speedup"
                            putOutput conn $ OutControl lvl [Ping]
      Nothing -> do
          statelessReset <- isStateessReset conn hdr crypt
          if statelessReset then do
              qlogReceived conn StatelessReset tim
              connDebugLog conn "Connection is reset statelessly"
              setCloseReceived conn
              E.throwTo (connThreadId conn) ConnectionIsReset
            else do
              qlogDropped conn hdr
              connDebugLog conn $ "Cannot decrypt: " <> bhow lvl <> " size = " <> bhow (BS.length $ cryptPacket crypt)
              -- fixme: sending statelss reset

processFrame :: Connection -> EncryptionLevel -> Frame -> IO ()
processFrame _ _ Padding{} = return ()
processFrame conn lvl Ping =
    putOutput conn $ OutControl lvl []
processFrame conn lvl (Ack ackInfo ackDelay) = do
    when (lvl == RTT0Level) $ do
        sendCCandExitConnection conn ProtocolViolation "ACK" 0x02 -- fixme
    onAckReceived (connLDCC conn) lvl ackInfo $ milliToMicro ackDelay
processFrame conn lvl (ResetStream sid aerr _finlen) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCandExitConnection conn ProtocolViolation "RESET_STREAM" 0x04
    when ((isClient conn && isClientInitiatedUnidirectional sid)
        ||(isServer conn && isServerInitiatedUnidirectional sid)) $
        sendCCandExitConnection conn StreamStateError "Send-only stream" 0x04
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> return ()
      Just strm -> onResetStreamReceived (connHooks conn) strm aerr
    connDebugLog conn "ResetStream" -- fixme
processFrame conn lvl (StopSending sid _err) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCandExitConnection conn ProtocolViolation "STOP_SENDING" 0x05
    when ((isClient conn && isServerInitiatedUnidirectional sid)
        ||(isServer conn && isClientInitiatedUnidirectional sid)) $
        sendCCandExitConnection conn StreamStateError "Receive-only stream" 0x05
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> do
          when ((isClient conn && isClientInitiated sid)
              ||(isServer conn && isServerInitiated sid)) $
              sendCCandExitConnection conn StreamStateError "No such stream for STOP_SENDING" 0x05
      Just _strm -> connDebugLog conn "StopSending" -- fixme
processFrame conn lvl (CryptoF off cdat) = do
    when (lvl == RTT0Level) $ do
        sendCCandExitConnection conn ProtocolViolation "CRYPTO" 0x06
    let len = BS.length cdat
        rx = RxStreamData cdat off len False
    case lvl of
      InitialLevel   -> do
          dup <- putRxCrypto conn lvl rx
          when dup $ speedup (connLDCC conn) lvl "duplicated"
      RTT0Level -> do
          connDebugLog conn $ "processFrame: invalid packet type " <> bhow lvl
      HandshakeLevel -> do
          dup <- putRxCrypto conn lvl rx
          when dup $ speedup (connLDCC conn) lvl "duplicated"
      RTT1Level
        | isClient conn ->
              void $ putRxCrypto conn lvl rx
        | otherwise ->
              sendCCandExitConnection conn (cryptoError UnexpectedMessage) "CRYPTO in 1-RTT" 0x06
processFrame conn lvl (NewToken token) = do
    when (isServer conn || lvl /= RTT1Level) $
        sendCCandExitConnection conn ProtocolViolation "NEW_TOKEN" 0x07
    setNewToken conn token
processFrame conn RTT0Level (StreamF sid off (dat:_) fin) = do
    strm <- getStream conn sid
    let len = BS.length dat
        rx = RxStreamData dat off len fin
    ok <- putRxStreamData strm rx
    if ok then
        addRxData conn $ BS.length dat             -- fixme: including 0RTT?
      else
        sendCCandExitConnection conn FlowControlError "" 0
processFrame conn RTT1Level (StreamF sid off (dat:_) fin) = do
    strm <- getStream conn sid
    let len = BS.length dat
        rx = RxStreamData dat off len fin
    ok <- putRxStreamData strm rx
    if ok then do
        addRxStreamData strm $ BS.length dat
        window <- getRxStreamWindow strm
        let initialWindow = initialRxMaxStreamData conn sid
        when (window <= (initialWindow .>>. 1)) $ do
            newMax <- addRxMaxStreamData strm initialWindow
            putOutput conn $ OutControl RTT1Level [MaxStreamData sid newMax]
            fire (Microseconds 50000) $ do
                newMax' <- getRxMaxStreamData strm
                putOutput conn $ OutControl RTT1Level [MaxStreamData sid newMax']
        addRxData conn $ BS.length dat
        cwindow <- getRxDataWindow conn
        let cinitialWindow = initialMaxData $ getMyParameters conn
        when (cwindow <= (cinitialWindow .>>. 1)) $ do
            newMax <- addRxMaxData conn cinitialWindow
            putOutput conn $ OutControl RTT1Level [MaxData newMax]
            fire (Microseconds 50000) $ do
                newMax' <- getRxMaxData conn
                putOutput conn $ OutControl RTT1Level [MaxData newMax']
      else
        sendCCandExitConnection conn FlowControlError "" 0
processFrame conn lvl (MaxData n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCandExitConnection conn ProtocolViolation "MAX_DATA" 0x010
    setTxMaxData conn n
processFrame conn lvl (MaxStreamData sid n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCandExitConnection conn ProtocolViolation "MAX_STREAM_DATA" 0x011
    when ((isClient conn && isServerInitiatedUnidirectional sid)
        ||(isServer conn && isClientInitiatedUnidirectional sid)) $
        sendCCandExitConnection conn StreamStateError "Receive-only stream" 0x11
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> do
          when ((isClient conn && isClientInitiated sid)
              ||(isServer conn && isServerInitiated sid)) $
              sendCCandExitConnection conn StreamStateError "No such stream for MAX_STREAM_DATA" 0x11
      Just strm -> setTxMaxStreamData strm n
processFrame conn lvl (MaxStreams dir n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCandExitConnection conn ProtocolViolation "MAX_STREAMS" 0
    when (n > 2^(60 :: Int)) $
        sendCCandExitConnection conn FrameEncodingError "MAX_STREAMS" 0
    if dir == Bidirectional then
        setMyMaxStreams conn n
      else
        setMyUniMaxStreams conn n
processFrame conn lvl DataBlocked{} = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCandExitConnection conn ProtocolViolation "DATA_BLOCKED" 0x14
    newMax <- getRxMaxData conn
    putOutput conn $ OutControl RTT1Level [MaxData newMax]
    fire (Microseconds 50000) $ do
        newMax' <- getRxMaxData conn
        putOutput conn $ OutControl RTT1Level [MaxData newMax']
processFrame conn lvl (StreamDataBlocked sid _) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCandExitConnection conn ProtocolViolation "STREAM_DATA_BLOCKED" 0x15
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> return ()
      Just strm -> do
          newMax <- getRxMaxStreamData strm
          putOutput conn $ OutControl RTT1Level [MaxStreamData sid newMax]
          fire (Microseconds 50000) $ do
              newMax' <- getRxMaxStreamData strm
              putOutput conn $ OutControl RTT1Level [MaxStreamData sid newMax']
processFrame conn lvl frame@(StreamsBlocked _dir n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCandExitConnection conn ProtocolViolation "STREAMS_BLOCKED" 0
    when (n > 2^(60 :: Int)) $
        sendCCandExitConnection conn FrameEncodingError "MAX_STREAMS" 0
    print frame
processFrame conn lvl (NewConnectionID cidInfo rpt) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCandExitConnection conn ProtocolViolation "NEW_CONNECTION_ID" 0x18
    addPeerCID conn cidInfo
    let (_, cidlen) = unpackCID $ cidInfoCID cidInfo
    when (cidlen < 1 || 20 < cidlen || rpt > cidInfoSeq cidInfo) $
        sendCCandExitConnection conn FrameEncodingError "NEW_CONNECTION_ID" 0x18
    when (rpt >= 1) $ do
        seqNums <- setPeerCIDAndRetireCIDs conn rpt
        let frames = map RetireConnectionID seqNums
        putOutput conn $ OutControl RTT1Level frames
processFrame conn RTT1Level (RetireConnectionID sn) = do
    mcidInfo <- retireMyCID conn sn
    when (isServer conn) $ case mcidInfo of
      Nothing -> return ()
      Just (CIDInfo _ cid _) -> do
          unregister <- getUnregister conn
          unregister cid
processFrame conn RTT1Level (PathChallenge dat) =
    putOutput conn $ OutControl RTT1Level [PathResponse dat]
processFrame conn RTT1Level (PathResponse dat) =
    -- RTT0Level falls intentionally
    checkResponse conn dat
processFrame conn _ (ConnectionClose err _ftyp reason)
  | err == NoError = do
        setCloseReceived conn
        onCloseReceived $ connHooks conn
        sent <- isCloseSent conn
        unless sent $ do
            sendFrame conn $ ConnectionClose NoError 0 ""
            -- if sent, client/server already exits.
            exitConnection conn ConnectionIsClosed
  | otherwise = do
        sent <- isCloseSent conn
        unless sent $ sendFrame conn $ ConnectionClose NoError 0 ""
        received <- isCloseReceived conn
        unless received $ do
            setCloseReceived conn
            let quicexc = TransportErrorIsReceived err reason
            exitConnection conn quicexc
processFrame conn _ (ConnectionCloseApp err reason) = do
    sent <- isCloseSent conn
    unless sent $ sendFrame conn $ ConnectionClose NoError 0 ""
    received <- isCloseReceived conn
    unless received $ do
        setCloseReceived conn
        let quicexc = ApplicationProtocolErrorIsReceived err reason
        exitConnection conn quicexc
processFrame conn lvl HandshakeDone = do
    when (isServer conn || lvl /= RTT1Level) $
        sendCCandExitConnection conn ProtocolViolation "HANDSHAKE_DONE" 0x1e
    onPacketNumberSpaceDiscarded (connLDCC conn) HandshakeLevel
    fire (Microseconds 100000) $ do
        dropSecrets conn RTT0Level
        dropSecrets conn HandshakeLevel
        clearCryptoStream conn HandshakeLevel
        clearCryptoStream conn RTT1Level
    setConnectionEstablished conn
    -- to receive NewSessionTicket
    fire (Microseconds 1000000) $ killHandshaker conn
processFrame conn _ _ = sendCCandExitConnection conn ProtocolViolation "" 0

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

putRxCrypto :: Connection -> EncryptionLevel -> RxStreamData -> IO Bool
putRxCrypto conn lvl rx = handleLogR logAction $ do
    strm <- getCryptoStream conn lvl
    (dats,_,duplicated) <- tryReassemble strm rx
    unless (null dats) $ mapM_ (putCrypto conn . InpHandshake lvl) dats
    return duplicated
  where
    logAction _ = do
        stdoutLogger ("No crypto stearm entry for " <> bhow lvl)
        return False
