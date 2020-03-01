{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Qlog where

import qualified Data.ByteString as BS
import Data.List
import Network.QUIC.Types

class Qlog a where
    qlog :: a -> String

instance Qlog RetryPacket where
    qlog RetryPacket{} = "{\"packet_type\":\"retry\",\"header\":{\"packet_number\":\"\"}}"

instance Qlog VersionNegotiationPacket where
    qlog VersionNegotiationPacket{} = "{\"packet_type\":\"version_negotiation\",\"header\":{\"packet_number\":\"\"}}"

instance Qlog PlainPacket where
    qlog (PlainPacket hdr Plain{..}) = "{\"packet_type\":\"" ++ packetType hdr ++ "\",\"frames\":" ++ "[" ++ intercalate "," (map qlog plainFrames) ++ "]" ++ ",\"header\":{\"packet_number\":\"" ++ show plainPacketNumber ++ "\"}}"

packetType :: Header -> String
packetType Initial{}   = "initial"
packetType RTT0{}      = "0RTT"
packetType Handshake{} = "handshake"
packetType Short{}     = "1RTT"

instance Qlog Frame where
    qlog frame = "{\"frame_type\":\"" ++ frameType frame ++ "\"" ++ frameExtra frame ++ "}"

frameType :: Frame -> String
frameType (Padding _) = "padding"
frameType  Ping = "ping"
frameType (Ack _AckInfo _Delay) = "ack"
frameType (ResetStream) = "reset_stream"
frameType (StopSending _StreamID _ApplicationError) = "stop_sending"
frameType (Crypto _Offset _CryptoData) = "crypto"
frameType (NewToken _Token) = "new_token"
frameType (Stream _StreamID _Offset _StreamData _Fin) = "stream"
frameType (MaxData _Int) = "max_data"
frameType (MaxStreamData _StreamID _Int) = "max_stream_data"
frameType (MaxStreams _Direction _Int) = "max_streams"
frameType (DataBlocked) = "data_blocked"
frameType (StreamDataBlocked) = "stream_data_blocked"
frameType (StreamsBlocked) = "streams_blocked"
frameType (NewConnectionID _Int _Int' _CID _StatelessResetToken) = "new_connection_id"
frameType (RetireConnectionID _Int) = "retire_connection_id"
frameType (PathChallenge _PathData) = "path_challenge"
frameType (PathResponse _PathData) = "patch_response"
frameType (ConnectionCloseQUIC _TransportError _FrameType _ReasonPhrase) = "connection_close"
frameType (ConnectionCloseApp _ApplicationError _ReasonPhrase) = "connection_close"
frameType (HandshakeDone) = "handshake_done"
frameType (UnknownFrame _Int) = "unknown"

frameExtra :: Frame -> String
frameExtra (Padding _) = ""
frameExtra  Ping = ""
frameExtra (Ack ai _Delay) = ",\"acked_ranges\":" ++ ack (fromAckInfo ai)
frameExtra (ResetStream) = ""
frameExtra (StopSending _StreamID _ApplicationError) = ""
frameExtra (Crypto off dat) =  ",\"offset\":\"" ++ show off ++ "\",\"length\":" ++ show (BS.length dat)
frameExtra (NewToken _Token) = ""
frameExtra (Stream sid off dat fin) = ",\"stream_id\":\"" ++ show sid ++ "\",\"offset\":\"" ++ show off ++ "\",\"length\":" ++ show (BS.length dat) ++ ",\"fin\":" ++ if fin then "true" else "false"
frameExtra (MaxData _Int) = ""
frameExtra (MaxStreamData _StreamID _Int) = ""
frameExtra (MaxStreams _Direction _Int) = ""
frameExtra (DataBlocked) = ""
frameExtra (StreamDataBlocked) = ""
frameExtra (StreamsBlocked) = ""
frameExtra (NewConnectionID _Int _Int' _CID _StatelessResetToken) = ""
frameExtra (RetireConnectionID _Int) = ""
frameExtra (PathChallenge _PathData) = ""
frameExtra (PathResponse _PathData) = ""
frameExtra (ConnectionCloseQUIC _TransportError _FrameType _ReasonPhrase) = ""
frameExtra (ConnectionCloseApp _ApplicationError _ReasonPhrase) = ""
frameExtra (HandshakeDone) = ""
frameExtra (UnknownFrame _Int) = ""

ack :: [PacketNumber] -> String
ack ps = "[" ++ intercalate "," (map shw (chop ps)) ++ "]"
  where
    shw [] = ""
    shw [n] = "[\"" ++ show n ++ "\"]"
    shw ns  = "[\"" ++ show (head ns) ++ "\",\"" ++ show (last ns) ++ "\"]"

chop :: [PacketNumber] -> [[PacketNumber]]
chop [] = []
chop xxs@(x:xs) = frst : rest
  where
    (ys,zs) = span (\(a,b) -> a - b == 1) $ zip xs xxs
    frst = x : map fst ys
    rest = chop $ map fst zs

qlogPrologue :: String -> CID -> String
qlogPrologue role oCID = "{\"qlog_version\":\"draft-01\"\n,\"traces\":[\n  {\"vantage_point\":{\"name\":\"Haskell quic\",\"type\":\"" ++ role ++ "\"}\n  ,\"common_fields\":{\"protocol_type\":\"QUIC_HTTP3\",\"reference_time\":\"0\",\"group_id\":\"" ++ ocid ++ "\",\"ODCID\":\"" ++ ocid ++ "\"}\n  ,\"event_fields\":[\"relative_time\",\"category\",\"event\",\"data\"]\n  ,\"events\":["
  where
    ocid = show oCID

qlogEpilogue :: String
qlogEpilogue = "[]]}]}"

qlogReceived :: Qlog a => a -> String
qlogReceived pkt = "[0,\"transport\",\"packet_received\"," ++ qlog pkt ++ "],"

qlogSent :: Qlog a => a -> String
qlogSent pkt = "[0,\"transport\",\"packet_sent\"," ++ qlog pkt ++ "],"
