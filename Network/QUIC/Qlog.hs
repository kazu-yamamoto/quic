{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Qlog where

import Data.List
import Network.QUIC.Types

class Qlog a where
    qlog :: a -> String

instance Qlog PlainPacket where
    qlog (PlainPacket hdr Plain{..}) = "{\"packet_type\":\"" ++ packetType hdr ++ "\",\"frames\":" ++ "[" ++ intercalate "," (map qlog plainFrames) ++ "]" ++ ",\"header\":{\"packet_number\":\"" ++ show plainPacketNumber ++ "\"}}"

packetType :: Header -> String
packetType Initial{}   = "initial"
packetType RTT0{}      = "0RTT"
packetType Handshake{} = "handshake"
packetType Short{}     = "1RTT"

instance Qlog Frame where
    qlog frame = "{\"frame_type\":\"" ++ frameType frame ++ "\"}"

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
