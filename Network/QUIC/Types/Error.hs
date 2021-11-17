{-# LANGUAGE PatternSynonyms #-}

module Network.QUIC.Types.Error where

import qualified Network.TLS as TLS
import Network.TLS.QUIC

-- | Transport errors of QUIC.
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

pattern VersionNegotiationError :: TransportError
pattern VersionNegotiationError  = TransportError 0x53f8

-- | Converting a TLS alert to a corresponding transport error.
cryptoError :: TLS.AlertDescription -> TransportError
cryptoError ad = TransportError ec
  where
    ec = 0x100 + fromIntegral (fromAlertDescription ad)

-- | Application protocol errors of QUIC.
newtype ApplicationProtocolError = ApplicationProtocolError Int deriving (Eq, Show)
