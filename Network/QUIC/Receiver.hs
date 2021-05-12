{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver (
    receiver
  ) where

import qualified Control.Exception as E
import qualified Data.ByteString as BS
import Foreign.Marshal.Alloc
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
import Network.QUIC.Types

receiver :: Connection -> Receive -> IO ()
receiver conn recv = handleLogT logAction $
    E.bracket (mallocBytes maximumUdpPayloadSize)
              free
              body
  where
    body buf = do
        loopHandshake buf
        loopEstablished buf
    recvTimeout = do
        -- The spec says that CC is not sent when timeout.
        -- But we intentionally sends CC when timeout.
        ito <- readMinIdleTimeout conn
        mx <- timeout ito recv -- fixme: taking minimum with peer's one
        case mx of
          Nothing -> E.throwIO ConnectionIsTimeout
          Just x  -> return x
    loopHandshake buf = do
        rpkt <- recvTimeout
        processReceivedPacketHandshake conn buf rpkt
        established <- isConnectionEstablished conn
        unless established $ loopHandshake buf
    loopEstablished buf = forever $ do
        rpkt <- recvTimeout
        let CryptPacket hdr _ = rpCryptPacket rpkt
            cid = headerMyCID hdr
        included <- myCIDsInclude conn cid
        case included of
          Just nseq -> do
            shouldUpdate <- shouldUpdateMyCID conn nseq
            when shouldUpdate $ setMyCID conn cid
            processReceivedPacket conn buf rpkt
            shouldUpdatePeer <- if shouldUpdate then shouldUpdatePeerCID conn
                                                else return False
            when shouldUpdatePeer $ choosePeerCIDForPrivacy conn
          _ -> do
            qlogDropped conn hdr
            connDebugLog conn $ bhow cid <> " is unknown"
    logAction msg = connDebugLog conn ("debug: receiver: " <> msg)

processReceivedPacketHandshake :: Connection -> Buffer -> ReceivedPacket -> IO ()
processReceivedPacketHandshake conn buf rpkt = do
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
              processReceivedPacket conn buf rpkt
        | otherwise -> do
              mycid <- getMyCID conn
              when (lvl == HandshakeLevel
                    || (lvl == InitialLevel && mycid == headerMyCID hdr)) $ do
                  setAddressValidated conn
              when (lvl == HandshakeLevel) $ do
                  let ldcc = connLDCC conn
                  discarded <- getAndSetPacketNumberSpaceDiscarded ldcc InitialLevel
                  unless discarded $ do
                      dropSecrets conn InitialLevel
                      clearCryptoStream conn InitialLevel
                      onPacketNumberSpaceDiscarded ldcc InitialLevel
              processReceivedPacket conn buf rpkt

processReceivedPacket :: Connection -> Buffer -> ReceivedPacket -> IO ()
processReceivedPacket conn buf rpkt = do
    let CryptPacket hdr crypt = rpCryptPacket rpkt
        lvl = rpEncryptionLevel rpkt
        tim = rpTimeRecevied rpkt
        bufsiz = maximumUdpPayloadSize
    mplain <- decryptCrypt conn buf bufsiz crypt lvl
    case mplain of
      Just plain@Plain{..} -> do
          lvl0 <- getEncryptionLevel conn
          when (isIllegalReservedBits plainMarks || isNoFrames plainMarks) $
              sendCCFrameAndBreak conn lvl0 ProtocolViolation "Non 0 RR bits or no frames" 0
          when (isUnknownFrame plainMarks) $
              sendCCFrameAndBreak conn lvl0 FrameEncodingError "Unknown frame" 0
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
              connDebugLog conn ("debug: drop packet whose size is " <> bhow (rpReceivedBytes rpkt))
              qlogDropped conn hdr
            else do
              (ckp,cpn) <- getCurrentKeyPhase conn
              let Flags flags = plainFlags
                  nkp = flags `testBit` 2
              when (nkp /= ckp && plainPacketNumber > cpn) $ do
                  setCurrentKeyPhase conn nkp plainPacketNumber
                  updateCoder1RTT conn ckp -- ckp is now next
              mapM_ (processFrame conn lvl) plainFrames
              when ackEli $ do
                  case lvl of
                    RTT0Level -> return ()
                    RTT1Level -> delayedAck conn
                    _         -> do
                        sup <- getSpeedingUp (connLDCC conn)
                        when sup $ do
                            qlogDebug conn $ Debug "ping for speedup"
                            sendFrames conn lvl [Ping]
      Nothing -> do
          statelessReset <- isStateessReset conn hdr crypt
          if statelessReset then do
              qlogReceived conn StatelessReset tim
              connDebugLog conn "debug: connection is reset statelessly"
              E.throwIO ConnectionIsReset
            else do
              qlogDropped conn hdr
              connDebugLog conn $ "debug: cannot decrypt: " <> bhow lvl <> " size = " <> bhow (BS.length $ cryptPacket crypt)
              -- fixme: sending statelss reset

processFrame :: Connection -> EncryptionLevel -> Frame -> IO ()
processFrame _ _ Padding{} = return ()
processFrame conn lvl Ping = do
    -- see ackEli above
    when (lvl /= RTT1Level) $ sendFrames conn lvl []
processFrame conn lvl (Ack ackInfo ackDelay) = do
    when (lvl == RTT0Level) $ do
        sendCCFrameAndBreak conn lvl ProtocolViolation "ACK" 0x02 -- fixme
    onAckReceived (connLDCC conn) lvl ackInfo $ milliToMicro ackDelay
processFrame conn lvl (ResetStream sid aerr _finlen) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCFrameAndBreak conn lvl ProtocolViolation "RESET_STREAM" 0x04
    when ((isClient conn && isClientInitiatedUnidirectional sid)
        ||(isServer conn && isServerInitiatedUnidirectional sid)) $
        sendCCFrameAndBreak conn lvl StreamStateError "Received in a send-only stream" 0x04
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> return ()
      Just strm -> onResetStreamReceived (connHooks conn) strm aerr
    connDebugLog conn "ResetStream" -- fixme
processFrame conn lvl (StopSending sid _err) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCFrameAndBreak conn lvl ProtocolViolation "STOP_SENDING" 0x05
    when ((isClient conn && isServerInitiatedUnidirectional sid)
        ||(isServer conn && isClientInitiatedUnidirectional sid)) $
        sendCCFrameAndBreak conn lvl StreamStateError "Receive-only stream" 0x05
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> do
          when ((isClient conn && isClientInitiated sid)
              ||(isServer conn && isServerInitiated sid)) $
              sendCCFrameAndBreak conn lvl StreamStateError "No such stream for STOP_SENDING" 0x05
      Just _strm -> connDebugLog conn "StopSending" -- fixme
processFrame _ _ (CryptoF _ "") = return ()
processFrame conn lvl (CryptoF off cdat) = do
    when (lvl == RTT0Level) $ do
        sendCCFrameAndBreak conn InitialLevel ProtocolViolation "CRYPTO in 0-RTT" 0x06
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
              sendCCFrameAndBreak conn lvl (cryptoError UnexpectedMessage) "CRYPTO in 1-RTT" 0x06
processFrame conn lvl (NewToken token) = do
    when (isServer conn || lvl /= RTT1Level) $
        sendCCFrameAndBreak conn lvl ProtocolViolation "NEW_TOKEN for server or in 1-RTT" 0x07
    when (isClient conn) $ setNewToken conn token
processFrame conn lvl@RTT0Level (StreamF sid off (dat:_) fin) = do
    when ((isClient conn && isClientInitiatedUnidirectional sid)
        ||(isServer conn && isServerInitiatedUnidirectional sid)) $
        sendCCFrameAndBreak conn lvl StreamStateError "send-only stream" 0
    mstrm <- findStream conn sid
    when (isNothing mstrm &&
          ((isClient conn && isClientInitiated sid) ||
           (isServer conn && isServerInitiated sid))) $
        sendCCFrameAndBreak conn lvl StreamStateError "a locally-initiated stream that has not yet been created" 0
    strm <- maybe (createStream conn sid) return mstrm
    let len = BS.length dat
        rx = RxStreamData dat off len fin
    ok <- putRxStreamData strm rx
    lvl0 <- getEncryptionLevel conn
    unless ok $ sendCCFrameAndBreak conn lvl0 FlowControlError "Flow control error in 0-RTT" 0
processFrame conn lvl@RTT1Level (StreamF sid _ [""] False) = do
    when ((isClient conn && isClientInitiatedUnidirectional sid)
        ||(isServer conn && isServerInitiatedUnidirectional sid)) $
        sendCCFrameAndBreak conn lvl StreamStateError "send-only stream" 0
    mstrm <- findStream conn sid
    when (isNothing mstrm &&
          ((isClient conn && isClientInitiated sid) ||
           (isServer conn && isServerInitiated sid))) $
        sendCCFrameAndBreak conn lvl StreamStateError "a locally-initiated stream that has not yet been created" 0
processFrame conn lvl@RTT1Level (StreamF sid off (dat:_) fin) = do
    when ((isClient conn && isClientInitiatedUnidirectional sid)
        ||(isServer conn && isServerInitiatedUnidirectional sid)) $
        sendCCFrameAndBreak conn lvl StreamStateError "send-only stream" 0
    mstrm <- findStream conn sid
    when (isNothing mstrm &&
          ((isClient conn && isClientInitiated sid) ||
           (isServer conn && isServerInitiated sid))) $
        sendCCFrameAndBreak conn lvl StreamStateError "a locally-initiated stream that has not yet been created" 0
    strm <- maybe (createStream conn sid) return mstrm
    let len = BS.length dat
        rx = RxStreamData dat off len fin
    ok <- putRxStreamData strm rx
    unless ok $ sendCCFrameAndBreak conn RTT1Level FlowControlError "Flow control error in 1-RTT" 0
processFrame conn lvl (MaxData n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCFrameAndBreak conn lvl ProtocolViolation "MAX_DATA in Initial or Handshake" 0x010
    setTxMaxData conn n
processFrame conn lvl (MaxStreamData sid n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCFrameAndBreak conn lvl ProtocolViolation "MAX_STREAM_DATA in Initial or Handshake" 0x011
    when ((isClient conn && isServerInitiatedUnidirectional sid)
        ||(isServer conn && isClientInitiatedUnidirectional sid)) $
        sendCCFrameAndBreak conn lvl StreamStateError "Receive-only stream" 0x11
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> do
          when ((isClient conn && isClientInitiated sid)
              ||(isServer conn && isServerInitiated sid)) $
              sendCCFrameAndBreak conn lvl StreamStateError "No such stream for MAX_STREAM_DATA" 0x11
      Just strm -> setTxMaxStreamData strm n
processFrame conn lvl (MaxStreams dir n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCFrameAndBreak conn lvl ProtocolViolation "MAX_STREAMS in Initial or Handshake" 0
    when (n > 2^(60 :: Int)) $
        sendCCFrameAndBreak conn lvl FrameEncodingError "Too large MAX_STREAMS" 0
    if dir == Bidirectional then
        setMyMaxStreams conn n
      else
        setMyUniMaxStreams conn n
processFrame _conn _lvl DataBlocked{} = return ()
processFrame _conn _lvl (StreamDataBlocked _sid _) = return ()
processFrame conn lvl (StreamsBlocked _dir n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCFrameAndBreak conn lvl ProtocolViolation "STREAMS_BLOCKED in Initial or Handshake" 0
    when (n > 2^(60 :: Int)) $
        sendCCFrameAndBreak conn lvl FrameEncodingError "Too large STREAMS_BLOCKED" 0
processFrame conn lvl (NewConnectionID cidInfo rpt) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        sendCCFrameAndBreak conn lvl ProtocolViolation "NEW_CONNECTION_ID in Initial or Handshake" 0x18
    addPeerCID conn cidInfo
    let (_, cidlen) = unpackCID $ cidInfoCID cidInfo
    when (cidlen < 1 || 20 < cidlen || rpt > cidInfoSeq cidInfo) $
        sendCCFrameAndBreak conn lvl FrameEncodingError "NEW_CONNECTION_ID parameter error" 0x18
    when (rpt >= 1) $ do
        seqNums <- setPeerCIDAndRetireCIDs conn rpt
        sendFrames conn RTT1Level $ map RetireConnectionID seqNums
processFrame conn RTT1Level (RetireConnectionID sn) = do
    mcidInfo <- retireMyCID conn sn
    case mcidInfo of
      Nothing -> return ()
      Just (CIDInfo _ cid _) -> do
          when (isServer conn) $ do
              unregister <- getUnregister conn
              unregister cid
          cidInfo <- getNewMyCID conn
          when (isServer conn) $ do
              register <- getRegister conn
              register (cidInfoCID cidInfo) conn
          sendFrames conn RTT1Level [NewConnectionID cidInfo 0]
processFrame conn RTT1Level (PathChallenge dat) =
    sendFrames conn RTT1Level [PathResponse dat]
processFrame conn RTT1Level (PathResponse dat) =
    -- RTT0Level falls intentionally
    checkResponse conn dat
processFrame conn _lvl (ConnectionClose err _ftyp reason)
  | err == NoError = do
        onCloseReceived $ connHooks conn
        when (isServer conn) $ E.throwIO ConnectionIsClosed
  | otherwise = do
        let quicexc = TransportErrorIsReceived err reason
        E.throwIO quicexc
processFrame conn _lvl (ConnectionCloseApp err reason) = do
    let quicexc = ApplicationProtocolErrorIsReceived err reason
    E.throwIO quicexc
processFrame conn lvl HandshakeDone
  | isServer conn || lvl /= RTT1Level =
        sendCCFrameAndBreak conn lvl ProtocolViolation "HANDSHAKE_DONE for server" 0x1e
  | otherwise = do
        fire conn (Microseconds 100000) $ do
            let ldcc = connLDCC conn
            discarded0 <- getAndSetPacketNumberSpaceDiscarded ldcc RTT0Level
            unless discarded0 $ dropSecrets conn RTT0Level
            discarded1 <- getAndSetPacketNumberSpaceDiscarded ldcc HandshakeLevel
            unless discarded1 $ do
                dropSecrets conn HandshakeLevel
                onPacketNumberSpaceDiscarded ldcc HandshakeLevel
            clearCryptoStream conn HandshakeLevel
            clearCryptoStream conn RTT1Level
        setConnectionEstablished conn
        -- to receive NewSessionTicket
        fire conn (Microseconds 1000000) $ killHandshaker conn lvl
processFrame conn lvl _ = sendCCFrameAndBreak conn lvl ProtocolViolation "Frame is not allowed" 0

-- QUIC version 1 uses only short packets for stateless reset.
-- But we should check other packets, too.
isStateessReset :: Connection -> Header -> Crypt -> IO Bool
isStateessReset conn header Crypt{..} = do
    included <- myCIDsInclude conn $ headerMyCID header
    case included of
      Just _ -> return False
      _      -> case decodeStatelessResetToken cryptPacket of
             Nothing    -> return False
             Just token -> isStatelessRestTokenValid conn token

-- Return value indicates duplication.
putRxCrypto :: Connection -> EncryptionLevel -> RxStreamData -> IO Bool
putRxCrypto conn lvl rx = do
    mstrm <- getCryptoStream conn lvl
    case mstrm of
      Nothing   -> return False
      Just strm -> do
          let put = putCrypto conn . InpHandshake lvl
              putFin = return ()
          tryReassemble strm rx put putFin

killHandshaker :: Connection -> EncryptionLevel -> IO ()
killHandshaker conn lvl = putCrypto conn $ InpHandshake lvl ""
