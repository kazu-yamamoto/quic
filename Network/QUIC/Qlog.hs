{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Qlog where

import qualified Control.Exception as E
import Control.Concurrent.STM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as Short
import Data.Hourglass
import Data.List
import Time.System

import Network.QUIC.Imports
import Network.QUIC.Types

class Qlog a where
    qlog :: a -> String

instance Qlog RetryPacket where
    qlog RetryPacket{} = "{\"packet_type\":\"retry\",\"header\":{\"packet_number\":\"\"}}"

instance Qlog VersionNegotiationPacket where
    qlog VersionNegotiationPacket{} = "{\"packet_type\":\"version_negotiation\",\"header\":{\"packet_number\":\"\"}}"

instance Qlog CryptPacket where
    qlog (CryptPacket hdr _) = "{\"packet_type\":\"" ++ packetType hdr ++ "\"}"

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
frameType Padding{}             = "padding"
frameType Ping                  = "ping"
frameType Ack{}                 = "ack"
frameType ResetStream{}         = "reset_stream"
frameType StopSending{}         = "stop_sending"
frameType Crypto{}              = "crypto"
frameType NewToken{}            = "new_token"
frameType Stream{}              = "stream"
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
frameExtra NewConnectionID{} = ""
frameExtra (RetireConnectionID _Int) = ""
frameExtra (PathChallenge _PathData) = ""
frameExtra (PathResponse _PathData) = ""
frameExtra (ConnectionCloseQUIC err _FrameType reason) = ",\"error_space\":\"transport\",\"error_code\":\"" ++ transportError err ++ "\",\"raw_error_code\":" ++ show (fromTransportError err) ++ ",\"reason\":\"" ++ C8.unpack (Short.fromShort reason) ++ "\""
frameExtra (ConnectionCloseApp _err reason) =  ",\"error_space\":\"transport\",\"error_code\":\"" ++ "\",\"raw_error_code\":" ++ show (0 :: Int) ++ ",\"reason\":\"" ++ C8.unpack (Short.fromShort reason) ++ "\"" -- fixme
frameExtra (HandshakeDone) = ""
frameExtra (UnknownFrame _Int) = ""

transportError :: TransportError -> String
transportError NoError                 = "no_error"
transportError InternalError           = "internal_error"
transportError ServerBusy              = "server_busy"
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

----------------------------------------------------------------

data QlogMsg = QRecvInitial
             | QSentRetry
             | QSent String
             | QReceived String
             | QDropped String

toString :: QlogMsg -> Int -> String
toString QRecvInitial _ =
    "[0,\"transport\",\"packet_received\",{\"packet_type\":\"initial\",\"header\":{\"packet_number\":\"\"}}],\n"
toString QSentRetry _ =
    "[0,\"transport\",\"packet_sent\",{\"packet_type\":\"retry\",\"header\":{\"packet_number\":\"\"}}],\n"
toString (QReceived msg) tim =
    "[" ++ show tim ++ ",\"transport\",\"packet_received\"," ++ msg ++ "],\n"
toString (QSent msg) tim =
    "[" ++ show tim ++ ",\"transport\",\"packet_sent\","     ++ msg ++ "],\n"
toString (QDropped msg) tim =
    "[" ++ show tim ++ ",\"transport\",\"packet_dropped\","  ++ msg ++ "],\n"

----------------------------------------------------------------

newtype QlogQ = QlogQ (TQueue QlogMsg)

newQlogQ :: IO QlogQ
newQlogQ = QlogQ <$> newTQueueIO

readQlogQ :: QlogQ -> IO QlogMsg
readQlogQ (QlogQ q) = atomically $ readTQueue q

writeQlogQ :: QlogQ -> QlogMsg -> IO ()
writeQlogQ (QlogQ q) msg = atomically $ writeTQueue q msg

newQlogger :: QlogQ -> String -> String -> (String -> IO ()) -> IO ()
newQlogger q rl ocid logAction = do
    getTime <- getElapsedTime <$> timeCurrentP
    logAction $ "{\"qlog_version\":\"draft-01\"\n,\"traces\":[\n  {\"vantage_point\":{\"name\":\"Haskell quic\",\"type\":\"" ++ rl ++ "\"}\n  ,\"common_fields\":{\"protocol_type\":\"QUIC_HTTP3\",\"reference_time\":\"0\",\"group_id\":\"" ++ ocid ++ "\",\"ODCID\":\"" ++ ocid ++ "\"}\n  ,\"event_fields\":[\"relative_time\",\"category\",\"event\",\"data\"]\n  ,\"events\":[\n"
    let body = do
            qmsg <- readQlogQ q
            tim <- getTime
            let msg = toString qmsg tim
            logAction msg `E.catch` ignore
    forever body `E.finally` logAction "[]]}]}\n"
  where
    ignore :: E.SomeException -> IO ()
    ignore _ = return ()

----------------------------------------------------------------

getElapsedTime :: ElapsedP -> IO Int
getElapsedTime base = do
    curr <- timeCurrentP
    return $ relativeTime base curr

relativeTime :: ElapsedP -> ElapsedP -> Int
relativeTime t1 t2 = fromIntegral (s * 1000 + (n `div` 1000000))
  where
   (Seconds s, NanoSeconds n) = t2 `timeDiffP` t1
