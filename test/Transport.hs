{-# LANGUAGE OverloadedStrings #-}

module Transport (
    transportSpec
  ) where

import Control.Concurrent
import Control.Monad
import Data.ByteString ()
import qualified Data.ByteString as BS
import Network.TLS (AlertDescription(..))
import Network.TLS.QUIC (ExtensionRaw)
import System.Timeout
import Test.Hspec

import Network.QUIC
import Network.QUIC.Internal

----------------------------------------------------------------

runC :: ClientConfig -> (Connection -> IO a) -> IO (Maybe a)
runC cc body = timeout 2000000 $ runQUICClient cc body

transportSpec :: ClientConfig -> SpecWith a
transportSpec cc0 = do
    describe "QUIC servers" $ do
        it "MUST send TRANSPORT_PARAMETER_ERROR if initial_source_connection_id is missing [Transport 7.3]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated dropInitialSourceConnectionId
            runC cc waitEstablished `shouldThrow` transportError TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if original_destination_connection_id is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setOriginalDestinationConnectionId
            runC cc waitEstablished `shouldThrow` transportError TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if preferred_address, is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setPreferredAddress
            runC cc waitEstablished `shouldThrow` transportError TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if retry_source_connection_id is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setRetrySourceConnectionId
            runC cc waitEstablished `shouldThrow` transportError TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if stateless_reset_token is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setStatelessResetToken
            runC cc waitEstablished `shouldThrow` transportError TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if max_udp_payload_size < 1200 [Transport 7.4 and 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setMaxUdpPayloadSize
            runC cc waitEstablished `shouldThrow` transportError TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if ack_delay_exponen > 20 [Transport 7.4 and 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setAckDelayExponent
            runC cc waitEstablished `shouldThrow` transportError TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if max_ack_delay >= 2^14 [Transport 7.4 and 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setMaxAckDelay
            runC cc waitEstablished `shouldThrow` transportError TransportParameterError
        it "MUST send FRAME_ENCODING_ERROR if a frame of unknown type is received [Transport 12.4]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated unknownFrame
            runC cc waitEstablished `shouldThrow` transportError FrameEncodingError
        it "MUST send PROTOCOL_VIOLATION on no frames [Transport 12.4]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated noFrames
            runC cc waitEstablished `shouldThrow` transportError ProtocolViolation
        it "MUST send PROTOCOL_VIOLATION if reserved bits in Handshake are non-zero [Transport 17.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ rrBits HandshakeLevel
            runC cc waitEstablished `shouldThrow` transportError ProtocolViolation
        it "MUST send PROTOCOL_VIOLATION if PATH_CHALLENGE in Handshake is received [Transport 17.2.4]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated handshakePathChallenge
            runC cc waitEstablished `shouldThrow` transportError ProtocolViolation
        it "MUST send PROTOCOL_VIOLATION if reserved bits in Short are non-zero [Transport 17.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ rrBits RTT1Level
            runC cc waitEstablished `shouldThrow` transportError ProtocolViolation
        it "MUST send PROTOCOL_VIOLATION if NEW_TOKEN is received [Transport 19.7]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated newToken
            runC cc waitEstablished `shouldThrow` transportError ProtocolViolation
        it "MUST send STREAM_STATE_ERROR if MAX_STREAM_DATA is received for a non-existing stream [Transport 19.10]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated maxStreamData
            runC cc waitEstablished `shouldThrow` transportError StreamStateError
        it "MUST send STREAM_STATE_ERROR if MAX_STREAM_DATA is received for a receive-only stream [Transport 19.10]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated maxStreamData2
            runC cc waitEstablished `shouldThrow` transportError StreamStateError
        it "MUST send FRAME_ENCODING_ERROR if invalid MAX_STREAMS is received [Transport 19.11]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated maxStreams
            runC cc waitEstablished `shouldThrow` transportError FrameEncodingError
        it "MUST send STREAM_LIMIT_ERROR or FRAME_ENCODING_ERROR if invalid STREAMS_BLOCKED is received [Transport 19.14]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated streamsBlocked
            runC cc waitEstablished `shouldThrow` transportErrors [FrameEncodingError,StreamLimitError]
        it "MUST send PROTOCOL_VIOLATION if HANDSHAKE_DONE is received [Transport 19.20]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated handshakeDone
            runC cc waitEstablished `shouldThrow` transportError ProtocolViolation
        it "MUST send unexpected_message TLS alert if KeyUpdate in Handshake is received [TLS 6]" $ \_ -> do
            let cc = addHook cc0 $ setOnTLSHandshakeCreated cryptoKeyUpdate
            runC cc waitEstablished `shouldThrow` transportError (CryptoError UnexpectedMessage)
        it "MUST send unexpected_message TLS alert if KeyUpdate in 1-RTT is received [TLS 6]" $ \_ -> do
            let cc = addHook cc0 $ setOnTLSHandshakeCreated cryptoKeyUpdate2
            runC cc (\conn -> waitEstablished conn >> threadDelay 1000000) `shouldThrow` transportErrors [CryptoError UnexpectedMessage, ProtocolViolation]
        it "MUST send no_application_protocol TLS alert if no application protocols are supported [TLS 8.1]" $ \_ -> do
            let cc = cc0 { ccALPN = \_ -> return $ Just ["dummy"] }
            runC cc waitEstablished `shouldThrow` transportError (CryptoError NoApplicationProtocol)
        it "MUST send missing_extension TLS alert if the quic_transport_parameters extension does not included [TLS 8.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTLSExtensionCreated (const [])
            runC cc waitEstablished `shouldThrow` transportError (CryptoError MissingExtension)
        it "MUST send unexpected_message TLS alert if EndOfEarlyData is received [TLS 8.3]" $ \_ -> do
            let cc = addHook cc0 $ setOnTLSHandshakeCreated cryptoEndOfEarlyData
            runC cc waitEstablished `shouldThrow` transportError (CryptoError UnexpectedMessage)
        it "MUST send PROTOCOL_VIOLATION if CRYPTO in 0-RTT is received [TLS 8.3]" $ \_ -> do
            mres <- runC cc0 $ \conn -> do
                waitEstablished conn
                getResumptionInfo conn
            case mres of
              Nothing -> return ()
              Just res -> when (is0RTTPossible res) $ do
                let cc1 = addHook cc0 $ setOnTLSHandshakeCreated crypto0RTT
                    cc = cc1 { ccResumption = res
                             , ccUse0RTT = True
                             }
                runC cc waitEstablished `shouldThrow` transportError ProtocolViolation

----------------------------------------------------------------

addHook :: ClientConfig -> (Hooks -> Hooks) -> ClientConfig
addHook cc modify = cc'
  where
    conf = ccConfig cc
    hooks = confHooks conf
    hooks' = modify hooks
    conf' = conf { confHooks = hooks' }
    cc' = cc { ccConfig = conf' }

setOnPlainCreated :: (EncryptionLevel -> Plain -> Plain) -> Hooks -> Hooks
setOnPlainCreated f hooks = hooks { onPlainCreated = f }

setOnTransportParametersCreated :: (Parameters -> Parameters) -> Hooks -> Hooks
setOnTransportParametersCreated f hooks = hooks { onTransportParametersCreated = f }

setOnTLSExtensionCreated :: ([ExtensionRaw] -> [ExtensionRaw]) -> Hooks -> Hooks
setOnTLSExtensionCreated f params = params { onTLSExtensionCreated = f }

setOnTLSHandshakeCreated :: ([(EncryptionLevel,CryptoData)] -> [(EncryptionLevel,CryptoData)]) -> Hooks -> Hooks
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
setPreferredAddress params = params { preferredAddress = Just "DUMMY" }

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

maxStreamData :: EncryptionLevel -> Plain -> Plain
maxStreamData lvl plain
  | lvl == RTT1Level = plain { plainFrames = MaxStreamData 102 1000000 : plainFrames plain }
  | otherwise = plain

maxStreamData2 :: EncryptionLevel -> Plain -> Plain
maxStreamData2 lvl plain
  | lvl == RTT1Level = plain { plainFrames = MaxStreamData 2 1000000 : plainFrames plain }
  | otherwise = plain

maxStreams :: EncryptionLevel -> Plain -> Plain
maxStreams lvl plain
  | lvl == RTT1Level = plain { plainFrames = MaxStreams Bidirectional (2^(60 :: Int) + 1) : plainFrames plain }
  | otherwise = plain

streamsBlocked :: EncryptionLevel -> Plain -> Plain
streamsBlocked lvl plain
  | lvl == RTT1Level = plain { plainFrames = StreamsBlocked Bidirectional (2^(60 :: Int) + 1) : plainFrames plain }
  | otherwise = plain

----------------------------------------------------------------

cryptoKeyUpdate :: [(EncryptionLevel,CryptoData)] -> [(EncryptionLevel,CryptoData)]
cryptoKeyUpdate [(HandshakeLevel,fin)] = [(HandshakeLevel,BS.append fin "\x18\x00\x00\x01\x01")]
cryptoKeyUpdate lcs = lcs

cryptoKeyUpdate2 :: [(EncryptionLevel,CryptoData)] -> [(EncryptionLevel,CryptoData)]
-- [] is intentionally created in RTT1Level for h3spec
cryptoKeyUpdate2 [] = [(RTT1Level,"\x18\x00\x00\x01\x01")]
cryptoKeyUpdate2 lcs = lcs

cryptoEndOfEarlyData :: [(EncryptionLevel,CryptoData)] -> [(EncryptionLevel,CryptoData)]
cryptoEndOfEarlyData [(HandshakeLevel,fin)] = [(HandshakeLevel,BS.append "\x05\x00\x00\x00" fin)]
cryptoEndOfEarlyData lcs = lcs

crypto0RTT :: [(EncryptionLevel,CryptoData)] -> [(EncryptionLevel,CryptoData)]
crypto0RTT [(InitialLevel,ch)] = [(InitialLevel,ch),(RTT0Level,"\x08\x00\x00\x02\x00\x00")]
crypto0RTT lcs = lcs

----------------------------------------------------------------

transportError :: TransportError -> QUICError -> Bool
transportError te (TransportErrorOccurs te' _) = te == te'
transportError _  _                            = False

transportErrors :: [TransportError] -> QUICError -> Bool
transportErrors tes (TransportErrorOccurs te _) = te `elem` tes
transportErrors _   _                           = False
