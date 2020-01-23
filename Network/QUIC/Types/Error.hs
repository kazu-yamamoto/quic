module Network.QUIC.Types.Error where

import qualified Control.Exception as E
import qualified Network.TLS as TLS
import Network.TLS.QUIC

import Network.QUIC.Imports

newtype ApplicationError = ApplicationError Int deriving (Eq, Show)

type ErrorCode = Int

data TransportError = NoError
                    | InternalError
                    | ServerBusy
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
                    | CryptoError TLS.AlertDescription
                    | UnknownError Int
                    deriving (Eq,Show)

fromTransportError :: TransportError -> ErrorCode
fromTransportError NoError                 = 0x0
fromTransportError InternalError           = 0x1
fromTransportError ServerBusy              = 0x2
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
fromTransportError (CryptoError desc)      =
    0x100 + fromIntegral (fromAlertDescription desc)
fromTransportError (UnknownError n)        = n

toTransportError :: ErrorCode -> TransportError
toTransportError 0x0 = NoError
toTransportError 0x1 = InternalError
toTransportError 0x2 = ServerBusy
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
toTransportError n
  | 0x100 <= n && n <= 0x1ff = case mdesc of
      Nothing   -> UnknownError n
      Just desc -> CryptoError desc
  | otherwise    = UnknownError n
  where
    mdesc = toAlertDescription $ fromIntegral (n - 0x100)

type ReasonPhrase = Bytes

data QUICError = PacketCannotBeDecrypted
               | VersionIsUnknown Word32
               | TransportErrorOccurs TransportError ReasonPhrase
               | ApplicationErrorOccurs ApplicationError ReasonPhrase
               | ConnectionIsNotOpen
               | HandshakeFailed String
               deriving (Eq, Show)

instance E.Exception QUICError
