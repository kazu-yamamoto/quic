{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE PatternSynonyms #-}

module Network.QUIC.Types.Error where

import Control.Exception as E
import Data.Typeable
import qualified Network.TLS as TLS
import Network.TLS.QUIC

import Network.QUIC.Imports

type ErrorCode = Int

newtype TransportError = TransportError Int deriving (Eq, Show)
instance Exception TransportError

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

type ReasonPhrase = Bytes

newtype ApplicationError = ApplicationError Int deriving (Eq, Show)

pattern H3NoError               :: ApplicationError
pattern H3NoError                = ApplicationError 0x100

pattern H3GeneralProtocolError  :: ApplicationError
pattern H3GeneralProtocolError   = ApplicationError 0x101

pattern H3InternalError         :: ApplicationError
pattern H3InternalError          = ApplicationError 0x102

pattern H3StreamCreationError   :: ApplicationError
pattern H3StreamCreationError    = ApplicationError 0x103

pattern H3ClosedCriticalStream  :: ApplicationError
pattern H3ClosedCriticalStream   = ApplicationError 0x104

pattern H3FrameUnexpected       :: ApplicationError
pattern H3FrameUnexpected        = ApplicationError 0x105

pattern H3FrameError            :: ApplicationError
pattern H3FrameError             = ApplicationError 0x106

pattern H3ExcessiveLoad         :: ApplicationError
pattern H3ExcessiveLoad          = ApplicationError 0x107

pattern H3IdError               :: ApplicationError
pattern H3IdError                = ApplicationError 0x108

pattern H3SettingsError         :: ApplicationError
pattern H3SettingsError          = ApplicationError 0x109

pattern H3MissingSettings       :: ApplicationError
pattern H3MissingSettings        = ApplicationError 0x10A

pattern H3RequestRejected       :: ApplicationError
pattern H3RequestRejected        = ApplicationError 0x10B

pattern H3RequestCancelled      :: ApplicationError
pattern H3RequestCancelled       = ApplicationError 0x10C

pattern H3RequestIncomplete     :: ApplicationError
pattern H3RequestIncomplete      = ApplicationError 0x10D

pattern H3ConnectError          :: ApplicationError
pattern H3ConnectError           = ApplicationError 0x10F

pattern H3VersionFallback       :: ApplicationError
pattern H3VersionFallback        = ApplicationError 0x110

pattern QpackDecompressionFailed :: ApplicationError
pattern QpackDecompressionFailed = ApplicationError 0x200

pattern QpackEncoderStreamError :: ApplicationError
pattern QpackEncoderStreamError  = ApplicationError 0x201

pattern QpackDecoderStreamError :: ApplicationError
pattern QpackDecoderStreamError  = ApplicationError 0x202
