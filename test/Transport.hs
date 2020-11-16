{-# LANGUAGE OverloadedStrings #-}

module Transport (
    transportSpec
  ) where

import Data.ByteString ()
import System.Timeout
import Test.Hspec
import Network.TLS (AlertDescription(..))

import Network.QUIC
import Network.QUIC.Internal

runC :: ClientConfig -> (Connection -> IO a) -> IO (Maybe a)
runC cc body = timeout 2000000 $ runQUICClient cc body

transportSpec :: ClientConfig -> SpecWith a
transportSpec cc0 = do
    describe "QUIC servers" $ do
        it "MUST send TRANSPORT_PARAMETER_ERROR if initial_source_connection_id is missing [Transport 7.3]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated dropInitialSourceConnectionId
            runC cc waitEstablished `shouldThrow` check TransportParameterError
        it "MUST send TRANSPORT_PARAMETER_ERROR if max_udp_payload_size is invalid [Transport 7.4 and 18.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnTransportParametersCreated setMaxUdpPayloadSize
            runC cc waitEstablished `shouldThrow` check TransportParameterError
        it "MUST send FRAME_ENCODING_ERROR if a frame of unknown type is received [Transport 12.4]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ unknownFrame RTT1Level
            runC cc waitEstablished `shouldThrow` check FrameEncodingError
        it "MUST send PROTOCOL_VIOLATION if reserved bits in Initial are non-zero [Transport 17.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ rrBits InitialLevel
            runC cc waitEstablished `shouldThrow` check ProtocolViolation
        it "MUST send PROTOCOL_VIOLATION if reserved bits in Handshake are non-zero [Transport 17.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ rrBits HandshakeLevel
            runC cc waitEstablished `shouldThrow` check ProtocolViolation
        it "MUST send PROTOCOL_VIOLATION if reserved bits in Short are non-zero [Transport 17.2]" $ \_ -> do
            let cc = addHook cc0 $ setOnPlainCreated $ rrBits RTT1Level
            runC cc waitEstablished `shouldThrow` check ProtocolViolation
        it "MUST send no_application_protocol TLS alert if no application protocols are supported" $ \_ -> do
            let cc = cc0 { ccALPN = \_ -> return $ Just ["dummy"] }
            runC cc waitEstablished `shouldThrow` check (CryptoError NoApplicationProtocol)

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

rrBits :: EncryptionLevel -> EncryptionLevel -> Plain -> Plain
rrBits lvl0 lvl plain
  | lvl0 == lvl = if plainPacketNumber plain /= 0 then
                    plain { plainFlags = Flags 0x08 }
                  else
                    plain
  | otherwise   = plain

setOnTransportParametersCreated :: (Parameters -> Parameters) -> Hooks -> Hooks
setOnTransportParametersCreated f hooks = hooks { onTransportParametersCreated = f }

dropInitialSourceConnectionId :: Parameters -> Parameters
dropInitialSourceConnectionId params = params { initialSourceConnectionId = Nothing }

setMaxUdpPayloadSize :: Parameters -> Parameters
setMaxUdpPayloadSize params = params { maxUdpPayloadSize = 1090 }

unknownFrame :: EncryptionLevel -> EncryptionLevel -> Plain -> Plain
unknownFrame lvl0 lvl plain
  | lvl0 == lvl = plain { plainFrames = UnknownFrame 0x20 : plainFrames plain }
  | otherwise   = plain

check :: TransportError -> QUICError -> Bool
check te (TransportErrorOccurs te' _) = te == te'
check _  _                            = False
