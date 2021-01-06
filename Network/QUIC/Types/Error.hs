{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE PatternSynonyms #-}

module Network.QUIC.Types.Error where

import Control.Exception as E
import Data.Typeable
import qualified Network.TLS as TLS
import Network.TLS.QUIC

import Network.QUIC.Imports

type ErrorCode = Int

data TransportError = NoError
                    | InternalError
                    | ConnectionRefused
                    | FlowControlError
                    | StreamLimitError
                    | StreamStateError
                    | FinalSizeError
                    | FrameEncodingError
                    | TransportParameterError
                    | ConnectionIdLimitError
                    | ProtocolViolation
                    | InvalidToken
                    | CryptoBufferExceeded
                    | KeyUpdateError
                    | AeadLimitReached
                    | NoViablePath
                    | CryptoError TLS.AlertDescription
                    | UnknownError Int
                    deriving (Eq,Show,Typeable)

instance Exception TransportError

fromTransportError :: TransportError -> ErrorCode
fromTransportError NoError                 = 0x0
fromTransportError InternalError           = 0x1
fromTransportError ConnectionRefused       = 0x2
fromTransportError FlowControlError        = 0x3
fromTransportError StreamLimitError        = 0x4
fromTransportError StreamStateError        = 0x5
fromTransportError FinalSizeError          = 0x6
fromTransportError FrameEncodingError      = 0x7
fromTransportError TransportParameterError = 0x8
fromTransportError ConnectionIdLimitError  = 0x9
fromTransportError ProtocolViolation       = 0xa
fromTransportError InvalidToken            = 0xb
fromTransportError CryptoBufferExceeded    = 0xd
fromTransportError KeyUpdateError          = 0xe
fromTransportError AeadLimitReached        = 0xf
fromTransportError NoViablePath            = 0x10
fromTransportError (CryptoError desc)      =
    0x100 + fromIntegral (fromAlertDescription desc)
fromTransportError (UnknownError n)        = n

toTransportError :: ErrorCode -> TransportError
toTransportError 0x0 = NoError
toTransportError 0x1 = InternalError
toTransportError 0x2 = ConnectionRefused
toTransportError 0x3 = FlowControlError
toTransportError 0x4 = StreamLimitError
toTransportError 0x5 = StreamStateError
toTransportError 0x6 = FinalSizeError
toTransportError 0x7 = FrameEncodingError
toTransportError 0x8 = TransportParameterError
toTransportError 0x9 = ConnectionIdLimitError
toTransportError 0xa = ProtocolViolation
toTransportError 0xb = InvalidToken
toTransportError 0xd = CryptoBufferExceeded
toTransportError 0xe = KeyUpdateError
toTransportError 0xf = AeadLimitReached
toTransportError 0x10 = NoViablePath
toTransportError n
  | 0x100 <= n && n <= 0x1ff = case mdesc of
      Nothing   -> UnknownError n
      Just desc -> CryptoError desc
  | otherwise    = UnknownError n
  where
    mdesc = toAlertDescription $ fromIntegral (n - 0x100)

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
