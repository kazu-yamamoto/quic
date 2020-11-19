{-# LANGUAGE OverloadedStrings #-}

module Transport (
    transportSpec
  ) where

import Data.ByteString ()
import System.Timeout
import Test.Hspec
import Network.TLS (AlertDescription(..))
import Network.TLS.QUIC (ExtensionRaw)

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
            runC cc waitEstablished `shouldThrow` check TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if original_destination_connection_id is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setOriginalDestinationConnectionId
            runC cc waitEstablished `shouldThrow` check TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if preferred_address, is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setPreferredAddress
            runC cc waitEstablished `shouldThrow` check TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if retry_source_connection_id is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setRetrySourceConnectionId
            runC cc waitEstablished `shouldThrow` check TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if stateless_reset_token is received [Transport 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setStatelessResetToken
            runC cc waitEstablished `shouldThrow` check TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if max_udp_payload_size is invalid [Transport 7.4 and 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setMaxUdpPayloadSize
            runC cc waitEstablished `shouldThrow` check TransportParameterError
        it "MUST send FRAME_ENCODING_ERROR if a frame of unknown type is received [Transport 12.4]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated unknownFrame
            runC cc waitEstablished `shouldThrow` check FrameEncodingError
        it "MUST send PROTOCOL_VIOLATION on no frames [Transport 12.4]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated noFrames
            runC cc waitEstablished `shouldThrow` check ProtocolViolation
        it "MUST send PROTOCOL_VIOLATION if reserved bits in Handshake are non-zero [Transport 17.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ rrBits HandshakeLevel
            runC cc waitEstablished `shouldThrow` check ProtocolViolation
        it "MUST send PROTOCOL_VIOLATION if reserved bits in Short are non-zero [Transport 17.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ rrBits RTT1Level
            runC cc waitEstablished `shouldThrow` check ProtocolViolation
        it "MUST send PROTOCOL_VIOLATION if NEW_TOKEN is received [Transport 19.7]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated newToken
            runC cc waitEstablished `shouldThrow` check ProtocolViolation
        it "MUST send PROTOCOL_VIOLATION if HANDSHAKE_DONE is received [Transport 19.20]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated handshakeDone
            runC cc waitEstablished `shouldThrow` check ProtocolViolation
        it "MUST send no_application_protocol TLS alert if no application protocols are supported [TLS 8.1]" $ \_ -> do
            let cc = cc0 { ccALPN = \_ -> return $ Just ["dummy"] }
            runC cc waitEstablished `shouldThrow` check (CryptoError NoApplicationProtocol)
        it "MUST the send missing_extension TLS alert if the quic_transport_parameters extension does not included [TLS 8.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTLSExtensionCreated (const [])
            runC cc waitEstablished `shouldThrow` check (CryptoError MissingExtension)

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

setMaxUdpPayloadSize :: Parameters -> Parameters
setMaxUdpPayloadSize params = params { maxUdpPayloadSize = 1090 }

unknownFrame :: EncryptionLevel -> Plain -> Plain
unknownFrame lvl plain
  | lvl == RTT1Level = plain { plainFrames = UnknownFrame 0x20 : plainFrames plain }
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

----------------------------------------------------------------

check :: TransportError -> QUICError -> Bool
check te (TransportErrorOccurs te' _) = te == te'
check _  _                            = False
