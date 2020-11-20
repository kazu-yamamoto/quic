{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Qlog (
    QLogger
  , newQlogger
  , Qlog(..)
  , KeepQlog(..)
  , QlogMsg(..)
  , qlogReceived
  , qlogDropped
  , qlogRecvInitial
  , qlogSentRetry
  , qlogParamsSet
  , qlogDebug
  , Debug(..)
  , packetType
  , sw
  ) where

import qualified Control.Exception as E
import qualified Data.ByteString as BS

import qualified Data.ByteString.Short as Short
import Data.List (intersperse)
import System.Log.FastLogger

import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Types

class Qlog a where
    qlog :: a -> LogStr

newtype Debug = Debug String

instance Show Debug where
    show (Debug msg) = msg

instance Qlog Debug where
    qlog (Debug msg) = "{\"message\":" <> sw msg <> "}"

instance Qlog RetryPacket where
    qlog RetryPacket{} = "{\"packet_type\":\"retry\",\"header\":{\"packet_number\":\"\"}}"

instance Qlog VersionNegotiationPacket where
    qlog VersionNegotiationPacket{} = "{\"packet_type\":\"version_negotiation\",\"header\":{\"packet_number\":\"\"}}"

instance Qlog Header where
    qlog hdr = "{\"packet_type\":\"" <> packetType hdr <> "\"}"

instance Qlog CryptPacket where
    qlog (CryptPacket hdr _) = qlog hdr

instance Qlog PlainPacket where
    qlog (PlainPacket hdr Plain{..}) = "{\"packet_type\":\"" <> toLogStr (packetType hdr) <> "\",\"frames\":" <> "[" <> foldr1 (<>) (intersperse "," (map qlog plainFrames)) <> "]" <> ",\"header\":{\"packet_number\":\"" <> sw plainPacketNumber <> "\",\"dcid\":\"" <> sw (headerMyCID hdr) <> "\"}}"

instance Qlog StatelessReset where
    qlog StatelessReset = "{\"packet_type\":\"stateless_reset\",\"header\":{\"packet_number\":\"\"}}"

packetType :: Header -> LogStr
packetType Initial{}   = "initial"
packetType RTT0{}      = "0RTT"
packetType Handshake{} = "handshake"
packetType Short{}     = "1RTT"

instance Qlog Frame where
    qlog frame = "{\"frame_type\":\"" <> frameType frame <> "\"" <> frameExtra frame <> "}"

frameType :: Frame -> LogStr
frameType Padding{}             = "padding"
frameType Ping                  = "ping"
frameType Ack{}                 = "ack"
frameType ResetStream{}         = "reset_stream"
frameType StopSending{}         = "stop_sending"
frameType CryptoF{}             = "crypto"
frameType NewToken{}            = "new_token"
frameType StreamF{}             = "stream"
frameType MaxData{}             = "max_data"
frameType MaxStreamData{}       = "max_stream_data"
frameType MaxStreams{}          = "max_streams"
frameType DataBlocked{}         = "data_blocked"
frameType StreamDataBlocked{}   = "stream_data_blocked"
frameType StreamsBlocked{}      = "streams_blocked"
frameType NewConnectionID{}     = "new_connection_id"
frameType RetireConnectionID{}  = "retire_connection_id"
frameType PathChallenge{}       = "path_challenge"
frameType PathResponse{}        = "path_response"
frameType ConnectionCloseQUIC{} = "connection_close"
frameType ConnectionCloseApp{}  = "connection_close"
frameType HandshakeDone{}       = "handshake_done"
frameType UnknownFrame{}        = "unknown"

{-# INLINE frameExtra #-}
frameExtra :: Frame -> LogStr
frameExtra (Padding _) = ""
frameExtra  Ping = ""
frameExtra (Ack ai _Delay) = ",\"acked_ranges\":" <> ack (fromAckInfo ai)
frameExtra ResetStream{} = ""
frameExtra (StopSending _StreamId _ApplicationError) = ""
frameExtra (CryptoF off dat) =  ",\"offset\":\"" <> sw off <> "\",\"length\":" <> sw (BS.length dat)
frameExtra (NewToken _Token) = ""
frameExtra (StreamF sid off dat fin) = ",\"stream_id\":\"" <> sw sid <> "\",\"offset\":\"" <> sw off <> "\",\"length\":" <> sw (sum' $ map BS.length dat) <> ",\"fin\":" <> if fin then "true" else "false"
frameExtra (MaxData mx) = ",\"maximum\":\"" <> sw mx <> "\""
frameExtra (MaxStreamData sid mx) = ",\"stream_id\":\"" <> sw sid <> "\",\"maximum\":\"" <> sw mx <> "\""
frameExtra (MaxStreams _Direction ms) = ",\"maximum\":\"" <> sw ms <> "\""
frameExtra DataBlocked{} = ""
frameExtra StreamDataBlocked{} = ""
frameExtra StreamsBlocked{} = ""
frameExtra (NewConnectionID (CIDInfo sn cid _) _) = ",\"sequence_number\":\"" <> sw sn <> "\",\"connection_id:\":\"" <> sw cid <> "\""
frameExtra (RetireConnectionID sn) = ",\"sequence_number\":\"" <> sw sn <> "\""
frameExtra (PathChallenge _PathData) = ""
frameExtra (PathResponse _PathData) = ""
frameExtra (ConnectionCloseQUIC err _FrameType reason) = ",\"error_space\":\"transport\",\"error_code\":\"" <> toLogStr (transportError err) <> "\",\"raw_error_code\":" <> sw (fromTransportError err) <> ",\"reason\":\"" <> toLogStr (Short.fromShort reason) <> "\""
frameExtra (ConnectionCloseApp _err reason) =  ",\"error_space\":\"transport\",\"error_code\":\"" <> "\",\"raw_error_code\":" <> sw (0 :: Int) <> ",\"reason\":\"" <> toLogStr (Short.fromShort reason) <> "\"" -- fixme
frameExtra HandshakeDone{} = ""
frameExtra (UnknownFrame _Int) = ""

transportError :: TransportError -> LogStr
transportError NoError                 = "no_error"
transportError InternalError           = "internal_error"
transportError ConnectionRefused       = "connection_refused"
transportError FlowControlError        = "flow_control_error"
transportError StreamLimitError        = "stream_limit_error"
transportError StreamStateError        = "stream_state_error"
transportError FinalSizeError          = "final_size_error"
transportError FrameEncodingError      = "frame_encoding_error"
transportError TransportParameterError = "transport_parameter_err"
transportError ConnectionIdLimitError  = "connection_id_limit_error"
transportError ProtocolViolation       = "protocol_violation"
transportError InvalidToken            = "invalid_migration"
transportError CryptoBufferExceeded    = "crypto_buffer_exceeded"
transportError _                       = ""

{-# INLINE ack #-}
ack :: [PacketNumber] -> LogStr
ack ps = "[" <> foldr1 (<>) (intersperse "," (map shw (chop ps))) <> "]"
  where
    shw [] = ""
    shw [n] = "[\"" <> sw n <> "\"]"
    shw ns  = "[\"" <> sw (head ns) <> "\",\"" <> sw (last ns) <> "\"]"

chop :: [PacketNumber] -> [[PacketNumber]]
chop [] = []
chop xxs@(x:xs) = frst : rest
  where
    (ys,zs) = span (\(a,b) -> a - b == 1) $ zip xs xxs
    frst = x : map fst ys
    rest = chop $ map fst zs

----------------------------------------------------------------

instance Qlog (Parameters,String) where
    qlog (Parameters{..},owner) =
               "{\"owner\":\"" <> toLogStr owner
          <> "\",\"initial_max_data\":\"" <> sw initialMaxData
          <> "\",\"initial_max_stream_data_bidi_local\":\"" <> sw initialMaxStreamDataBidiLocal
          <> "\",\"initial_max_stream_data_bidi_remote\":\"" <> sw initialMaxStreamDataBidiRemote
          <> "\",\"initial_max_stream_data_uni\":\"" <> sw initialMaxStreamDataUni
          <> "\"}"

----------------------------------------------------------------

data QlogMsg = QRecvInitial
             | QSentRetry
             | QSent LogStr TimeMicrosecond
             | QReceived LogStr TimeMicrosecond
             | QDropped LogStr TimeMicrosecond
             | QMetricsUpdated LogStr TimeMicrosecond
             | QPacketLost LogStr TimeMicrosecond
             | QCongestionStateUpdated LogStr TimeMicrosecond
             | QLossTimerUpdated LogStr TimeMicrosecond
             | QDebug LogStr TimeMicrosecond
             | QParamsSet LogStr TimeMicrosecond

{-# INLINE toLogStrTime #-}
toLogStrTime :: QlogMsg -> TimeMicrosecond -> LogStr
toLogStrTime QRecvInitial _ =
    "[0,\"transport\",\"packet_received\",{\"packet_type\":\"initial\",\"header\":{\"packet_number\":\"\"}}],\n"
toLogStrTime QSentRetry _ =
    "[0,\"transport\",\"packet_sent\",{\"packet_type\":\"retry\",\"header\":{\"packet_number\":\"\"}}],\n"
toLogStrTime (QReceived msg tim) base =
    "[" <> swtim tim base <> ",\"transport\",\"packet_received\"," <> msg <> "],\n"
toLogStrTime (QSent msg tim) base =
    "[" <> swtim tim base <> ",\"transport\",\"packet_sent\","     <> msg <> "],\n"
toLogStrTime (QDropped msg tim) base =
    "[" <> swtim tim base <> ",\"transport\",\"packet_dropped\","  <> msg <> "],\n"
toLogStrTime (QParamsSet msg tim) base =
    "[" <> swtim tim base <> ",\"transport\",\"parameters_set\","  <> msg <> "],\n"
toLogStrTime (QMetricsUpdated msg tim) base =
    "[" <> swtim tim base <> ",\"recovery\",\"metrics_updated\","  <> msg <> "],\n"
toLogStrTime (QPacketLost msg tim) base =
    "[" <> swtim tim base <> ",\"recovery\",\"packet_lost\","      <> msg <> "],\n"
toLogStrTime (QCongestionStateUpdated msg tim) base =
    "[" <> swtim tim base <> ",\"recovery\",\"congestion_state_updated\"," <> msg <> "],\n"
toLogStrTime (QLossTimerUpdated msg tim) base =
    "[" <> swtim tim base <> ",\"recovery\",\"loss_timer_updated\"," <> msg <> "],\n"
toLogStrTime (QDebug msg tim) base =
    "[" <> swtim tim base <> ",\"debug\",\"debug\"," <> msg <> "],\n"

----------------------------------------------------------------

{-# INLINE sw #-}
sw :: Show a => a -> LogStr
sw = toLogStr . show

{-# INLINE swtim #-}
swtim :: TimeMicrosecond -> TimeMicrosecond -> LogStr
swtim tim base = toLogStr $ show x
  where
    Microseconds x = elapsedTimeMicrosecond tim base

----------------------------------------------------------------

type QLogger = QlogMsg -> IO ()

newQlogger :: TimeMicrosecond -> ByteString -> CID -> FastLogger -> IO QLogger
newQlogger base rl ocid fastLogger = do
    let ocid' = toLogStr $ enc16 $ fromCID ocid
    fastLogger $ "{\"qlog_version\":\"draft-01\"\n,\"traces\":[\n  {\"vantage_point\":{\"name\":\"Haskell quic\",\"type\":\"" <> toLogStr rl <> "\"}\n ,\"configuration\":{\"time_units\":\"us\"}\n ,\"common_fields\":{\"protocol_type\":\"QUIC_HTTP3\",\"reference_time\":\"0\",\"group_id\":\"" <> ocid' <> "\",\"ODCID\":\"" <> ocid' <> "\"}\n  ,\"event_fields\":[\"relative_time\",\"category\",\"event\",\"data\"]\n  ,\"events\":[\n"
    let qlogger qmsg = do
            let msg = toLogStrTime qmsg base
            fastLogger msg `E.catch` ignore
    return qlogger
  where
    ignore :: E.SomeException -> IO ()
    ignore _ = return ()

----------------------------------------------------------------

class KeepQlog a where
    keepQlog :: a -> QLogger

qlogReceived :: (KeepQlog q, Qlog a) => q -> a -> TimeMicrosecond -> IO ()
qlogReceived q pkt tim = keepQlog q $ QReceived (qlog pkt) tim

qlogDropped :: (KeepQlog q, Qlog a) => q -> a -> IO ()
qlogDropped q pkt = do
    tim <- getTimeMicrosecond
    keepQlog q $ QDropped (qlog pkt) tim

qlogRecvInitial :: KeepQlog q => q -> IO ()
qlogRecvInitial q = keepQlog q QRecvInitial

qlogSentRetry :: KeepQlog q => q -> IO ()
qlogSentRetry q = keepQlog q QSentRetry

qlogParamsSet :: KeepQlog q => q -> (Parameters,String) -> IO ()
qlogParamsSet q params = do
    tim <- getTimeMicrosecond
    keepQlog q $ QParamsSet (qlog params) tim

qlogDebug :: KeepQlog q => q -> Debug -> IO ()
qlogDebug q msg = do
    tim <- getTimeMicrosecond
    keepQlog q $ QDebug (qlog msg) tim
