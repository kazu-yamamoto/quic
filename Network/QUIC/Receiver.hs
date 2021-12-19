{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver (
    receiver
  ) where

import Control.Concurrent (forkIO)
import qualified Data.ByteString as BS
import Network.TLS (AlertDescription(..))
import qualified UnliftIO.Exception as E

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Crypto
import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Qlog
import Network.QUIC.Recovery
import Network.QUIC.Server.Reader (runNewServerReader)
import Network.QUIC.Stream
import Network.QUIC.Types

receiver :: Connection -> IO ()
receiver conn = handleLogT logAction body
  where
    body = do
        loopHandshake
        loopEstablished
    recvTimeout = do
        -- The spec says that CC is not sent when timeout.
        -- But we intentionally sends CC when timeout.
        ito <- readMinIdleTimeout conn
        mx <- timeout ito $ connRecv conn -- fixme: taking minimum with peer's one
        case mx of
          Nothing -> E.throwIO ConnectionIsTimeout
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
        case included of
          Just nseq -> do
            shouldUpdate <- shouldUpdateMyCID conn nseq
            when shouldUpdate $ do
                setMyCID conn cid
                cidInfo <- getNewMyCID conn
                when (isServer conn) $ do
                    register <- getRegister conn
                    register (cidInfoCID cidInfo) conn
                sendFrames conn RTT1Level [NewConnectionID cidInfo 0]
            processReceivedPacket conn rpkt
            shouldUpdatePeer <- if shouldUpdate then shouldUpdatePeerCID conn
                                                else return False
            when shouldUpdatePeer $ choosePeerCIDForPrivacy conn
          _ -> do
            qlogDropped conn hdr
            connDebugLog conn $ bhow cid <> " is unknown"
    logAction msg = connDebugLog conn ("debug: receiver: " <> msg)

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
              case hdr of
                Initial peerVer _ _ _ -> do
                    myVer <- getVersion conn
                    let myOrigiVer = getOriginalVersion conn
                        firstTime = myVer == myOrigiVer
                    when (firstTime && myVer /= peerVer) $ do
                        setVersion conn peerVer
                        initializeCoder conn InitialLevel $ initialSecrets peerVer $ clientDstCID conn
                _ -> return ()
              processReceivedPacket conn rpkt
        | otherwise -> do
              mycid <- getMyCID conn
              when (lvl == HandshakeLevel
                    || (lvl == InitialLevel && mycid == headerMyCID hdr)) $ do
                  setAddressValidated conn
              when (lvl == HandshakeLevel) $ do
                  let ldcc = connLDCC conn
                  discarded <- getAndSetPacketNumberSpaceDiscarded ldcc InitialLevel
                  unless discarded $ fire conn (Microseconds 100000) $ do
                      dropSecrets conn InitialLevel
                      clearCryptoStream conn InitialLevel
                      onPacketNumberSpaceDiscarded ldcc InitialLevel
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
              closeConnection ProtocolViolation "Non 0 RR bits or no frames"
          when (isUnknownFrame plainMarks) $
              closeConnection FrameEncodingError "Unknown frame"
          -- For Ping, record PPN first, then send an ACK.
          onPacketReceived (connLDCC conn) lvl plainPacketNumber
          when (lvl == RTT1Level) $ setPeerPacketNumber conn plainPacketNumber
          qlogReceived conn (PlainPacket hdr plain) tim
          let ackEli   = any ackEliciting   plainFrames
              shouldDrop = rpReceivedBytes rpkt < defaultQUICPacketSize
                        && lvl == InitialLevel && ackEli
          if shouldDrop then do
              connDebugLog conn ("debug: drop packet whose size is " <> bhow (rpReceivedBytes rpkt))
              qlogDropped conn hdr
            else do
              case cryptMigraionInfo crypt of
                Nothing -> return ()
                Just (MigrationInfo mysa peersa dCID) ->
                    void . forkIO $ runNewServerReader conn mysa peersa dCID
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
          statelessReset <- isStatelessReset conn hdr crypt
          if statelessReset then do
              qlogReceived conn StatelessReset tim
              connDebugLog conn "debug: connection is reset statelessly"
              E.throwIO ConnectionIsReset
            else do
              qlogDropped conn hdr
              connDebugLog conn $ "debug: cannot decrypt: " <> bhow lvl <> " size = " <> bhow (BS.length $ cryptPacket crypt)
              -- fixme: sending statelss reset

isSendOnly :: Connection -> StreamId -> Bool
isSendOnly conn sid
  | isClient conn = isClientInitiatedUnidirectional sid
  | otherwise     = isServerInitiatedUnidirectional sid

isReceiveOnly :: Connection -> StreamId -> Bool
isReceiveOnly conn sid
  | isClient conn = isServerInitiatedUnidirectional sid
  | otherwise     = isClientInitiatedUnidirectional sid

isInitiated :: Connection -> StreamId -> Bool
isInitiated conn sid
  | isClient conn = isClientInitiated sid
  | otherwise     = isServerInitiated sid

guardStream :: Connection -> StreamId -> Maybe Stream -> IO ()
guardStream conn sid Nothing
  | isInitiated conn sid = do
        curSid <- getMyStreamId conn
        when (sid > curSid) $
            closeConnection StreamStateError "a locally-initiated stream that has not yet been created"
guardStream _ _ _ = return ()

processFrame :: Connection -> EncryptionLevel -> Frame -> IO ()
processFrame _ _ Padding{} = return ()
processFrame conn lvl Ping = do
    -- see ackEli above
    when (lvl /= InitialLevel && lvl /= RTT1Level) $ sendFrames conn lvl []
processFrame conn lvl (Ack ackInfo ackDelay) = do
    when (lvl == RTT0Level) $ closeConnection ProtocolViolation "ACK"
    onAckReceived (connLDCC conn) lvl ackInfo $ milliToMicro ackDelay
processFrame conn lvl (ResetStream sid aerr _finlen) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection ProtocolViolation "RESET_STREAM"
    when (isSendOnly conn sid) $
        closeConnection StreamStateError "Received in a send-only stream"
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> return ()
      Just strm -> do
          onResetStreamReceived (connHooks conn) strm aerr
          setTxStreamClosed strm
          setRxStreamClosed strm
          delStream conn strm
processFrame conn lvl (StopSending sid err) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection ProtocolViolation "STOP_SENDING"
    when (isReceiveOnly conn sid) $
        closeConnection StreamStateError "Receive-only stream"
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> do
          when (isInitiated conn sid) $
              closeConnection StreamStateError "No such stream for STOP_SENDING"
      Just _strm -> sendFrames conn lvl [ResetStream sid err 0]
processFrame _ _ (CryptoF _ "") = return ()
processFrame conn lvl (CryptoF off cdat) = do
    when (lvl == RTT0Level) $
        closeConnection ProtocolViolation "CRYPTO in 0-RTT"
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
              closeConnection (cryptoError UnexpectedMessage) "CRYPTO in 1-RTT"
processFrame conn lvl (NewToken token) = do
    when (isServer conn || lvl /= RTT1Level) $
        closeConnection ProtocolViolation "NEW_TOKEN for server or in 1-RTT"
    when (isClient conn) $ setNewToken conn token
processFrame conn RTT0Level (StreamF sid off (dat:_) fin) = do
    when (isSendOnly conn sid) $
        closeConnection StreamStateError "send-only stream"
    mstrm <- findStream conn sid
    guardStream conn sid mstrm
    strm <- maybe (createStream conn sid) return mstrm
    let len = BS.length dat
        rx = RxStreamData dat off len fin
    ok <- putRxStreamData strm rx
    unless ok $ closeConnection FlowControlError "Flow control error in 0-RTT"
processFrame conn RTT1Level (StreamF sid _ [""] False) = do
    when (isSendOnly conn sid) $
        closeConnection StreamStateError "send-only stream"
    mstrm <- findStream conn sid
    guardStream conn sid mstrm
processFrame conn RTT1Level (StreamF sid off (dat:_) fin) = do
    when (isSendOnly conn sid) $
        closeConnection StreamStateError "send-only stream"
    mstrm <- findStream conn sid
    guardStream conn sid mstrm
    strm <- maybe (createStream conn sid) return mstrm
    let len = BS.length dat
        rx = RxStreamData dat off len fin
    ok <- putRxStreamData strm rx
    unless ok $ closeConnection FlowControlError "Flow control error in 1-RTT"
processFrame conn lvl (MaxData n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection ProtocolViolation "MAX_DATA in Initial or Handshake"
    setTxMaxData conn n
processFrame conn lvl (MaxStreamData sid n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection ProtocolViolation "MAX_STREAM_DATA in Initial or Handshake"
    when (isReceiveOnly conn sid) $
        closeConnection StreamStateError "Receive-only stream"
    mstrm <- findStream conn sid
    case mstrm of
      Nothing   -> do
          when (isInitiated conn sid) $
              closeConnection StreamStateError "No such stream for MAX_STREAM_DATA"
      Just strm -> setTxMaxStreamData strm n
processFrame conn lvl (MaxStreams dir n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection ProtocolViolation "MAX_STREAMS in Initial or Handshake"
    when (n > 2^(60 :: Int)) $
        closeConnection FrameEncodingError "Too large MAX_STREAMS"
    if dir == Bidirectional then
        setMyMaxStreams conn n
      else
        setMyUniMaxStreams conn n
processFrame _conn _lvl DataBlocked{} = return ()
processFrame _conn _lvl (StreamDataBlocked _sid _) = return ()
processFrame _conn lvl (StreamsBlocked _dir n) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection ProtocolViolation "STREAMS_BLOCKED in Initial or Handshake"
    when (n > 2^(60 :: Int)) $
        closeConnection FrameEncodingError "Too large STREAMS_BLOCKED"
processFrame conn lvl (NewConnectionID cidInfo rpt) = do
    when (lvl == InitialLevel || lvl == HandshakeLevel) $
        closeConnection ProtocolViolation "NEW_CONNECTION_ID in Initial or Handshake"
    addPeerCID conn cidInfo
    let (_, cidlen) = unpackCID $ cidInfoCID cidInfo
    when (cidlen < 1 || 20 < cidlen || rpt > cidInfoSeq cidInfo) $
        closeConnection FrameEncodingError "NEW_CONNECTION_ID parameter error"
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
processFrame conn RTT1Level (PathChallenge dat) =
    sendFrames conn RTT1Level [PathResponse dat]
processFrame conn RTT1Level (PathResponse dat) =
    -- RTT0Level falls intentionally
    checkResponse conn dat
processFrame conn _lvl (ConnectionClose NoError _ftyp _reason) =
    when (isServer conn) $ E.throwIO ConnectionIsClosed
processFrame _conn _lvl (ConnectionClose err _ftyp reason) = do
    let quicexc = TransportErrorIsReceived err reason
    E.throwIO quicexc
processFrame _conn _lvl (ConnectionCloseApp err reason) = do
    let quicexc = ApplicationProtocolErrorIsReceived err reason
    E.throwIO quicexc
processFrame conn lvl HandshakeDone = do
    when (isServer conn || lvl /= RTT1Level) $
        closeConnection ProtocolViolation "HANDSHAKE_DONE for server"
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
processFrame _ _ _ = closeConnection ProtocolViolation "Frame is not allowed"

-- QUIC version 1 uses only short packets for stateless reset.
-- But we should check other packets, too.
isStatelessReset :: Connection -> Header -> Crypt -> IO Bool
isStatelessReset conn hdr Crypt{..} = do
    let cid = headerMyCID hdr
    included <- myCIDsInclude conn cid
    case included of
      Just _ -> return False
      _      -> case decodeStatelessResetToken cryptPacket of
             Nothing    -> return False
             Just token -> isStatelessRestTokenValid conn cid token

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
