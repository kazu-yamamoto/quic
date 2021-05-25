{-# LANGUAGE OverloadedStrings #-}

module TransportError (
    transportErrorSpec
  ) where

import Control.Concurrent
import Control.Monad
import Data.ByteString ()
import qualified Data.ByteString as BS
import qualified Network.TLS as TLS
import Network.TLS.QUIC (ExtensionRaw)
import Test.Hspec
import UnliftIO.Timeout

import Network.QUIC
import Network.QUIC.Internal hiding (timeout)

----------------------------------------------------------------

type Millisecond = Int

runC :: ClientConfig -> Millisecond -> (Connection -> IO a) -> IO (Maybe a)
runC cc ms body = timeout us $ runQUICClient cc body'
  where
    us = ms * 1000
    body' conn = do
        waitEstablished conn
        threadDelay 100000
        body conn

runCnoOp :: ClientConfig -> Millisecond -> IO (Maybe ())
runCnoOp cc ms = timeout us $ runQUICClient cc body'
  where
    us = ms * 1000
    body' conn = do
        waitEstablished conn
        threadDelay us

transportErrorSpec :: ClientConfig -> Millisecond -> SpecWith a
transportErrorSpec cc0 ms = do
    describe "QUIC servers" $ do
        it "MUST send FLOW_CONTROL_ERROR if a STREAM frame with a large offset is received [Transport 4.1]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated largeOffset
            runCnoOp cc ms `shouldThrow` transportErrorsIn [FlowControlError]
        it "MUST send TRANSPORT_PARAMETER_ERROR if initial_source_connection_id is missing [Transport 7.3]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated dropInitialSourceConnectionId
            runCnoOp cc ms `shouldThrow` transportErrorsIn [TransportParameterError]
        it "MUST send TRANSPORT_PARAMETER_ERROR if original_destination_connection_id is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setOriginalDestinationConnectionId
            runCnoOp cc ms `shouldThrow` transportErrorsIn [TransportParameterError]
        it "MUST send TRANSPORT_PARAMETER_ERROR if preferred_address, is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setPreferredAddress
            runCnoOp cc ms `shouldThrow` transportErrorsIn [TransportParameterError]
        it "MUST send TRANSPORT_PARAMETER_ERROR if retry_source_connection_id is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setRetrySourceConnectionId
            runCnoOp cc ms `shouldThrow` transportErrorsIn [TransportParameterError]
        it "MUST send TRANSPORT_PARAMETER_ERROR if stateless_reset_token is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setStatelessResetToken
            runCnoOp cc ms `shouldThrow` transportErrorsIn [TransportParameterError]
        it "MUST send TRANSPORT_PARAMETER_ERROR if max_udp_payload_size < 1200 [Transport 7.4 and 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setMaxUdpPayloadSize
            runCnoOp cc ms `shouldThrow` transportErrorsIn [TransportParameterError]
        it "MUST send TRANSPORT_PARAMETER_ERROR if ack_delay_exponen > 20 [Transport 7.4 and 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setAckDelayExponent
            runCnoOp cc ms `shouldThrow` transportErrorsIn [TransportParameterError]
        it "MUST send TRANSPORT_PARAMETER_ERROR if max_ack_delay >= 2^14 [Transport 7.4 and 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setMaxAckDelay
            runCnoOp cc ms `shouldThrow` transportErrorsIn [TransportParameterError]
        it "MUST send FRAME_ENCODING_ERROR if a frame of unknown type is received [Transport 12.4]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated unknownFrame
            runCnoOp cc ms `shouldThrow` transportErrorsIn [FrameEncodingError]
        it "MUST send PROTOCOL_VIOLATION on no frames [Transport 12.4]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated noFrames
            runCnoOp cc ms `shouldThrow` transportError
        it "MUST send PROTOCOL_VIOLATION if reserved bits in Handshake are non-zero [Transport 17.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ rrBits HandshakeLevel
            runCnoOp cc ms `shouldThrow` transportError
        it "MUST send PROTOCOL_VIOLATION if PATH_CHALLENGE in Handshake is received [Transport 17.2.4]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated handshakePathChallenge
            runCnoOp cc ms `shouldThrow` transportError
        it "MUST send PROTOCOL_VIOLATION if reserved bits in Short are non-zero [Transport 17.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ rrBits RTT1Level
            runCnoOp cc ms `shouldThrow` transportError
        it "MUST send STREAM_STATE_ERROR if RESET_STREAM is received for a send-only stream [Transport 19.4]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated resetStrm
            runCnoOp cc ms `shouldThrow` transportErrorsIn [StreamStateError]
        it "MUST send STREAM_STATE_ERROR if STOP_SENDING is received for a non-existing stream [Transport 19.5]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated stopSending
            runCnoOp cc ms `shouldThrow` transportErrorsIn [StreamStateError]
        it "MUST send PROTOCOL_VIOLATION if NEW_TOKEN is received [Transport 19.7]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated newToken
            runCnoOp cc ms `shouldThrow` transportError
        it "MUST send STREAM_STATE_ERROR if it receives a STREAM frame for a locally-initiated stream that has not yet been created [Transport 19.8]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated localInitiatedNotCreatedYet
            runCnoOp cc ms `shouldThrow` transportErrorsIn [StreamStateError]
        it "MUST send STREAM_STATE_ERROR if it receives a STREAM frame for a send-only stream [Transport 19.8]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated sendOnlyStream
            runCnoOp cc ms `shouldThrow` transportErrorsIn [StreamStateError]
        it "MUST send STREAM_STATE_ERROR if MAX_STREAM_DATA is received for a non-existing stream [Transport 19.10]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated maxStreamData
            runCnoOp cc ms `shouldThrow` transportErrorsIn [StreamStateError]
        it "MUST send STREAM_STATE_ERROR if MAX_STREAM_DATA is received for a receive-only stream [Transport 19.10]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated maxStreamData2
            runCnoOp cc ms `shouldThrow` transportErrorsIn [StreamStateError]
        it "MUST send FRAME_ENCODING_ERROR if invalid MAX_STREAMS is received [Transport 19.11]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated maxStreams'
            runCnoOp cc ms `shouldThrow` transportErrorsIn [FrameEncodingError]
        it "MUST send STREAM_LIMIT_ERROR or FRAME_ENCODING_ERROR if invalid STREAMS_BLOCKED is received [Transport 19.14]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated streamsBlocked
            runCnoOp cc ms `shouldThrow` transportErrorsIn [FrameEncodingError,StreamLimitError]
        it "MUST send FRAME_ENCODING_ERROR if NEW_CONNECTION_ID with invalid Retire_Prior_To is received [Transport 19.15]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ newConnectionID ncidLargeRPT
            runCnoOp cc ms `shouldThrow` transportErrorsIn [FrameEncodingError]
        it "MUST send FRAME_ENCODING_ERROR if NEW_CONNECTION_ID with 0-byte CID is received [Transport 19.15]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ newConnectionID ncidZeroCID
            runCnoOp cc ms `shouldThrow` transportErrorsIn [FrameEncodingError]
        it "MUST send PROTOCOL_VIOLATION if HANDSHAKE_DONE is received [Transport 19.20]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated handshakeDone
            runCnoOp cc ms `shouldThrow` transportError
        it "MUST send unexpected_message TLS alert if KeyUpdate in Handshake is received [TLS 6]" $ \_ -> do
            let cc = addHook cc0 $ setOnTLSHandshakeCreated cryptoKeyUpdate
            runCnoOp cc ms `shouldThrow` cryptoErrorsIn [TLS.UnexpectedMessage]
        it "MUST send unexpected_message TLS alert if KeyUpdate in 1-RTT is received [TLS 6]" $ \_ -> do
            let cc = addHook cc0 $ setOnTLSHandshakeCreated cryptoKeyUpdate2
            runC cc ms (\_ -> threadDelay 1000000) `shouldThrow` cryptoErrorsIn [TLS.UnexpectedMessage]
        it "MUST send no_application_protocol TLS alert if no application protocols are supported [TLS 8.1]" $ \_ -> do
            let cc = cc0 { ccALPN = \_ -> return $ Just ["dummy"] }
            runCnoOp cc ms `shouldThrow` cryptoErrorsIn [TLS.NoApplicationProtocol]
        it "MUST send missing_extension TLS alert if the quic_transport_parameters extension does not included [TLS 8.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTLSExtensionCreated (const [])
            runCnoOp cc ms `shouldThrow` cryptoErrorsIn [TLS.MissingExtension]
        it "MUST send unexpected_message TLS alert if EndOfEarlyData is received [TLS 8.3]" $ \_ -> do
            let cc = addHook cc0 $ setOnTLSHandshakeCreated cryptoEndOfEarlyData
            runCnoOp cc ms `shouldThrow` cryptoErrorsIn [TLS.UnexpectedMessage]
        it "MUST send PROTOCOL_VIOLATION if CRYPTO in 0-RTT is received [TLS 8.3]" $ \_ -> do
            mres <- runC cc0 ms getResumptionInfo
            case mres of
              Just res
                | is0RTTPossible res -> do
                    let cc1 = addHook cc0 $ setOnTLSHandshakeCreated crypto0RTT
                        cc = cc1 { ccResumption = res
                                 , ccUse0RTT = True
                                 }
                    runCnoOp cc ms `shouldThrow` transportError
              _ -> do
                    putStrLn "Warning: 0-RTT is not possible. Skipping this test. Use \"h3spec -s 0-RTT\" next time."
                    when (ccDebugLog cc0) $ print mres

----------------------------------------------------------------

addHook :: ClientConfig -> (Hooks -> Hooks) -> ClientConfig
addHook cc modify = cc'
  where
    cc' = cc { ccHooks = modify $ ccHooks cc }

setOnPlainCreated :: (EncryptionLevel -> Plain -> Plain) -> Hooks -> Hooks
setOnPlainCreated f hooks = hooks { onPlainCreated = f }

setOnTransportParametersCreated :: (Parameters -> Parameters) -> Hooks -> Hooks
setOnTransportParametersCreated f hooks = hooks { onTransportParametersCreated = f }

setOnTLSExtensionCreated :: ([ExtensionRaw] -> [ExtensionRaw]) -> Hooks -> Hooks
setOnTLSExtensionCreated f params = params { onTLSExtensionCreated = f }

setOnTLSHandshakeCreated :: ([(EncryptionLevel,CryptoData)] -> ([(EncryptionLevel,CryptoData)],Bool)) -> Hooks -> Hooks
setOnTLSHandshakeCreated f hooks = hooks { onTLSHandshakeCreated = f }

----------------------------------------------------------------

rrBits :: EncryptionLevel -> EncryptionLevel -> Plain -> Plain
rrBits lvl0 lvl plain
  | lvl0 == lvl = if plainPacketNumber plain /= 0 then
                    plain { plainFlags = Flags 0x08 }
                  else
                    plain
  | otherwise   = plain

dropInitialSourceConnectionId :: Parameters -> Parameters
dropInitialSourceConnectionId params = params { initialSourceConnectionId = Nothing }

dummyCID :: Maybe CID
dummyCID = Just $ toCID "DUMMY"

setOriginalDestinationConnectionId :: Parameters -> Parameters
setOriginalDestinationConnectionId params = params { originalDestinationConnectionId = dummyCID }

setPreferredAddress :: Parameters -> Parameters
setPreferredAddress params = params { preferredAddress = Just prefAddr }
  where
    prefAddr = BS.concat
        [ "\x7f\x00\x00\x01"
        , "\x01\xbb"
        , "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        , "\x00\x00"
        , "\x08"
        , "\x00\x01\x02\x03\x04\x05\x06\x07"
        , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        ]

setRetrySourceConnectionId :: Parameters -> Parameters
setRetrySourceConnectionId params = params { retrySourceConnectionId = dummyCID }

setStatelessResetToken :: Parameters -> Parameters
setStatelessResetToken params = params { statelessResetToken = Just $ StatelessResetToken "DUMMY" }

----------------------------------------------------------------

setMaxUdpPayloadSize :: Parameters -> Parameters
setMaxUdpPayloadSize params = params { maxUdpPayloadSize = 1090 }

setAckDelayExponent :: Parameters -> Parameters
setAckDelayExponent params = params { ackDelayExponent = 30 }

setMaxAckDelay :: Parameters -> Parameters
setMaxAckDelay params = params { maxAckDelay = 2^(15 :: Int) }

----------------------------------------------------------------

largeOffset :: EncryptionLevel -> Plain -> Plain
largeOffset lvl plain
  | lvl == RTT1Level = plain { plainFrames = fake : plainFrames plain }
  | otherwise        = plain
  where
    fake = StreamF 0 100000000 ["GET /\r\n"] True

unknownFrame :: EncryptionLevel -> Plain -> Plain
unknownFrame lvl plain
  | lvl == RTT1Level = plain { plainFrames = UnknownFrame 0x20 : plainFrames plain }
  | otherwise        = plain

handshakePathChallenge :: EncryptionLevel -> Plain -> Plain
handshakePathChallenge lvl plain
  | lvl == HandshakeLevel = plain { plainFrames = PathChallenge (PathData "01234567") : plainFrames plain }
  | otherwise        = plain

noFrames :: EncryptionLevel -> Plain -> Plain
noFrames lvl plain
  | lvl == RTT1Level = plain { plainFrames = [], plainMarks = set4bytesPN $ setNoPaddings $ plainMarks plain }
  | otherwise        = plain

handshakeDone :: EncryptionLevel -> Plain -> Plain
handshakeDone lvl plain
  | lvl == RTT1Level = plain { plainFrames = HandshakeDone : plainFrames plain }
  | otherwise = plain

newToken :: EncryptionLevel -> Plain -> Plain
newToken lvl plain
  | lvl == RTT1Level = plain { plainFrames = NewToken "DUMMY" : plainFrames plain }
  | otherwise = plain

localInitiatedNotCreatedYet :: EncryptionLevel -> Plain -> Plain
localInitiatedNotCreatedYet lvl plain
  | lvl == RTT1Level = plain { plainFrames = StreamF 1 0 [""] False : plainFrames plain }
  | otherwise = plain

sendOnlyStream :: EncryptionLevel -> Plain -> Plain
sendOnlyStream lvl plain
  | lvl == RTT1Level = plain { plainFrames = StreamF 3 0 [""] False : plainFrames plain }
  | otherwise = plain

resetStrm :: EncryptionLevel -> Plain -> Plain
resetStrm lvl plain
  | lvl == RTT1Level = plain { plainFrames = ResetStream 3 (ApplicationProtocolError 0) 0 : plainFrames plain }
  | otherwise = plain

stopSending :: EncryptionLevel -> Plain -> Plain
stopSending lvl plain
  | lvl == RTT1Level = plain { plainFrames = StopSending 101 (ApplicationProtocolError 0) : plainFrames plain }
  | otherwise = plain

maxStreamData :: EncryptionLevel -> Plain -> Plain
maxStreamData lvl plain
  | lvl == RTT1Level = plain { plainFrames = MaxStreamData 101 1000000 : plainFrames plain }
  | otherwise = plain

maxStreamData2 :: EncryptionLevel -> Plain -> Plain
maxStreamData2 lvl plain
  | lvl == RTT1Level = plain { plainFrames = MaxStreamData 2 1000000 : plainFrames plain }
  | otherwise = plain

maxStreams' :: EncryptionLevel -> Plain -> Plain
maxStreams' lvl plain
  | lvl == RTT1Level = plain { plainFrames = MaxStreams Bidirectional (2^(60 :: Int) + 1) : plainFrames plain }
  | otherwise = plain

streamsBlocked :: EncryptionLevel -> Plain -> Plain
streamsBlocked lvl plain
  | lvl == RTT1Level = plain { plainFrames = StreamsBlocked Bidirectional (2^(60 :: Int) + 1) : plainFrames plain }
  | otherwise = plain

newConnectionID :: (Frame -> Frame) -> EncryptionLevel -> Plain -> Plain
newConnectionID f lvl plain
  | lvl == RTT1Level = plain { plainFrames = map f $ plainFrames plain }
  | otherwise = plain

ncidZeroCID :: Frame -> Frame
ncidZeroCID (NewConnectionID cidinfo0 rpt) = NewConnectionID cidinfo rpt
  where
    cidinfo = cidinfo0 { cidInfoCID = CID "" }
ncidZeroCID frame = frame

ncidLargeRPT :: Frame -> Frame
ncidLargeRPT (NewConnectionID cidinfo rpt) = NewConnectionID cidinfo (rpt + 10)
ncidLargeRPT frame = frame

----------------------------------------------------------------

cryptoKeyUpdate :: [(EncryptionLevel,CryptoData)] -> ([(EncryptionLevel,CryptoData)],Bool)
cryptoKeyUpdate [(HandshakeLevel,fin)] = ([(HandshakeLevel,BS.append fin "\x18\x00\x00\x01\x01")],False)
cryptoKeyUpdate lcs = (lcs,False)

cryptoKeyUpdate2 :: [(EncryptionLevel,CryptoData)] -> ([(EncryptionLevel,CryptoData)],Bool)
-- [] is intentionally created in RTT1Level for h3spec
cryptoKeyUpdate2 []  = ([(RTT1Level,"\x18\x00\x00\x01\x01")],False)
cryptoKeyUpdate2 lcs = (lcs,False)

cryptoEndOfEarlyData :: [(EncryptionLevel,CryptoData)] -> ([(EncryptionLevel,CryptoData)],Bool)
cryptoEndOfEarlyData [(HandshakeLevel,fin)] = ([(HandshakeLevel,BS.append "\x05\x00\x00\x00" fin)],False)
cryptoEndOfEarlyData lcs = (lcs,False)

crypto0RTT :: [(EncryptionLevel,CryptoData)] -> ([(EncryptionLevel,CryptoData)],Bool)
crypto0RTT [(InitialLevel,ch)] = ([(InitialLevel,ch),(RTT0Level,"\x08\x00\x00\x02\x00\x00")],True)
crypto0RTT lcs = (lcs,False)

----------------------------------------------------------------

transportError :: QUICException -> Bool
transportError (TransportErrorIsReceived te _) = te `elem` [ProtocolViolation, InternalError]
transportError _ = False

-- Transport Sec 11:
-- In particular, an endpoint MAY use any applicable error code when
-- it detects an error condition; a generic error code (such as
-- PROTOCOL_VIOLATION or INTERNAL_ERROR) can always be used in place
-- of specific error codes.
transportErrorsIn :: [TransportError] -> QUICException -> Bool
transportErrorsIn tes qe@(TransportErrorIsReceived te _) = (te `elem` tes) || transportError qe
transportErrorsIn _   _                           = False

cryptoErrorX :: QUICException -> Bool
cryptoErrorX (TransportErrorIsReceived te _) = te `elem` [cryptoError TLS.InternalError, cryptoError TLS.HandshakeFailure]
cryptoErrorX _ = False

-- Crypto Sec 4.8: QUIC permits the use of a generic code in place of
-- a specific error code; see Section 11 of [QUIC-TRANSPORT]. For TLS
-- alerts, this includes replacing any alert with a generic alert,
-- such as handshake_failure (0x128 in QUIC). Endpoints MAY use a
-- generic error code to avoid possibly exposing confidential
-- information.
cryptoErrorsIn :: [TLS.AlertDescription] -> QUICException -> Bool
cryptoErrorsIn tes qe@(TransportErrorIsReceived te _) = (te `elem` map cryptoError tes) || cryptoErrorX qe
cryptoErrorsIn _   _                           = False
