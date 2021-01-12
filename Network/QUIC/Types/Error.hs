{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE PatternSynonyms #-}

module Network.QUIC.Types.Error where

import qualified Network.TLS as TLS
import Network.TLS.QUIC

newtype TransportError = TransportError Int deriving (Eq, Show)

pattern NoError                 :: TransportError
pattern NoError                  = TransportError  0x0

pattern InternalError           :: TransportError
pattern InternalError            = TransportError  0x1

pattern ConnectionRefused       :: TransportError
pattern ConnectionRefused        = TransportError  0x2

pattern FlowControlError        :: TransportError
pattern FlowControlError         = TransportError  0x3

pattern StreamLimitError        :: TransportError
pattern StreamLimitError         = TransportError  0x4

pattern StreamStateError        :: TransportError
pattern StreamStateError         = TransportError  0x5

pattern FinalSizeError          :: TransportError
pattern FinalSizeError           = TransportError  0x6

pattern FrameEncodingError      :: TransportError
pattern FrameEncodingError       = TransportError  0x7

pattern TransportParameterError :: TransportError
pattern TransportParameterError  = TransportError  0x8

pattern ConnectionIdLimitError  :: TransportError
pattern ConnectionIdLimitError   = TransportError  0x9

pattern ProtocolViolation       :: TransportError
pattern ProtocolViolation        = TransportError  0xa

pattern InvalidToken            :: TransportError
pattern InvalidToken             = TransportError  0xb

pattern ApplicationError        :: TransportError
pattern ApplicationError         = TransportError  0xc

pattern CryptoBufferExceeded    :: TransportError
pattern CryptoBufferExceeded     = TransportError  0xd

pattern KeyUpdateError          :: TransportError
pattern KeyUpdateError           = TransportError  0xe

pattern AeadLimitReached        :: TransportError
pattern AeadLimitReached         = TransportError  0xf

pattern NoViablePath            :: TransportError
pattern NoViablePath             = TransportError 0x10

cryptoError :: TLS.AlertDescription -> TransportError
cryptoError ad = TransportError ec
  where
    ec = 0x100 + fromIntegral (fromAlertDescription ad)

newtype ApplicationProtocolError = ApplicationProtocolError Int deriving (Eq, Show)

pattern H3NoError                :: ApplicationProtocolError
pattern H3NoError                 = ApplicationProtocolError 0x100

pattern H3GeneralProtocolError   :: ApplicationProtocolError
pattern H3GeneralProtocolError    = ApplicationProtocolError 0x101

pattern H3InternalError          :: ApplicationProtocolError
pattern H3InternalError           = ApplicationProtocolError 0x102

pattern H3StreamCreationError    :: ApplicationProtocolError
pattern H3StreamCreationError     = ApplicationProtocolError 0x103

pattern H3ClosedCriticalStream   :: ApplicationProtocolError
pattern H3ClosedCriticalStream    = ApplicationProtocolError 0x104

pattern H3FrameUnexpected        :: ApplicationProtocolError
pattern H3FrameUnexpected         = ApplicationProtocolError 0x105

pattern H3FrameError             :: ApplicationProtocolError
pattern H3FrameError              = ApplicationProtocolError 0x106

pattern H3ExcessiveLoad          :: ApplicationProtocolError
pattern H3ExcessiveLoad           = ApplicationProtocolError 0x107

pattern H3IdError                :: ApplicationProtocolError
pattern H3IdError                 = ApplicationProtocolError 0x108

pattern H3SettingsError          :: ApplicationProtocolError
pattern H3SettingsError           = ApplicationProtocolError 0x109

pattern H3MissingSettings        :: ApplicationProtocolError
pattern H3MissingSettings         = ApplicationProtocolError 0x10A

pattern H3RequestRejected        :: ApplicationProtocolError
pattern H3RequestRejected         = ApplicationProtocolError 0x10B

pattern H3RequestCancelled       :: ApplicationProtocolError
pattern H3RequestCancelled        = ApplicationProtocolError 0x10C

pattern H3RequestIncomplete      :: ApplicationProtocolError
pattern H3RequestIncomplete       = ApplicationProtocolError 0x10D

pattern H3ConnectError           :: ApplicationProtocolError
pattern H3ConnectError            = ApplicationProtocolError 0x10F

pattern H3VersionFallback        :: ApplicationProtocolError
pattern H3VersionFallback         = ApplicationProtocolError 0x110

pattern QpackDecompressionFailed :: ApplicationProtocolError
pattern QpackDecompressionFailed  = ApplicationProtocolError 0x200

pattern QpackEncoderStreamError  :: ApplicationProtocolError
pattern QpackEncoderStreamError   = ApplicationProtocolError 0x201

pattern QpackDecoderStreamError  :: ApplicationProtocolError
pattern QpackDecoderStreamError   = ApplicationProtocolError 0x202
