module Network.QUIC.Transport.Error where

import qualified Network.TLS as TLS
import Network.TLS.QUIC

import Network.QUIC.Transport.Types

data QUICError = NoError
               | InternalError
               | ServerBusy
               | FlowControlError
               | StreamLimitError
               | StreamStateError
               | FinalSizeError
               | FrameEncodingError
               | TransportParameterError
               | ProtocolViolation
               | CryptoBufferExceeded
               | CryptoError TLS.AlertDescription
               | UnknownError Int
               deriving (Eq,Show)

fromQUICError :: QUICError -> ErrorCode
fromQUICError NoError                 = 0x0
fromQUICError InternalError           = 0x1
fromQUICError ServerBusy              = 0x2
fromQUICError FlowControlError        = 0x3
fromQUICError StreamLimitError        = 0x4
fromQUICError StreamStateError        = 0x5
fromQUICError FinalSizeError          = 0x6
fromQUICError FrameEncodingError      = 0x7
fromQUICError TransportParameterError = 0x8
fromQUICError ProtocolViolation       = 0x9
fromQUICError CryptoBufferExceeded    = 0xa
fromQUICError (CryptoError desc)      =
    0x100 + fromIntegral (fromAlertDescription desc)
fromQUICError (UnknownError n)        = n

toQUICError :: ErrorCode -> QUICError
toQUICError 0x0 = NoError
toQUICError 0x1 = InternalError
toQUICError 0x2 = ServerBusy
toQUICError 0x3 = FlowControlError
toQUICError 0x4 = StreamLimitError
toQUICError 0x5 = StreamStateError
toQUICError 0x6 = FinalSizeError
toQUICError 0x7 = FrameEncodingError
toQUICError 0x8 = TransportParameterError
toQUICError 0x9 = ProtocolViolation
toQUICError 0xa = CryptoBufferExceeded
toQUICError n
  | 0x100 <= n && n <= 0x1ff = case mdesc of
      Nothing   -> UnknownError n
      Just desc -> CryptoError desc
  | otherwise    = UnknownError n
  where
    mdesc = toAlertDescription $ fromIntegral (n - 0x100)
