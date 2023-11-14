{-# LANGUAGE PatternSynonyms #-}

module Network.QUIC.Types.Error where

import qualified Network.TLS as TLS
import Network.TLS.QUIC
import Text.Printf

-- | Transport errors of QUIC.
newtype TransportError = TransportError Int deriving (Eq)

{- FOURMOLU_DISABLE -}
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
pattern VersionNegotiationError  = TransportError 0x11

instance Show TransportError where
    show (TransportError    0x0) = "NoError"
    show (TransportError    0x1) = "InternalError"
    show (TransportError    0x2) = "ConnectionRefused"
    show (TransportError    0x3) = "FlowControlError"
    show (TransportError    0x4) = "StreamLimitError"
    show (TransportError    0x5) = "StreamStateError"
    show (TransportError    0x6) = "FinalSizeError"
    show (TransportError    0x7) = "FrameEncodingError"
    show (TransportError    0x8) = "TransportParameterError"
    show (TransportError    0x9) = "ConnectionIdLimitError"
    show (TransportError    0xa) = "ProtocolViolation"
    show (TransportError    0xb) = "InvalidToken"
    show (TransportError    0xc) = "ApplicationError"
    show (TransportError    0xd) = "CryptoBufferExceeded"
    show (TransportError    0xe) = "KeyUpdateError"
    show (TransportError    0xf) = "AeadLimitReached"
    show (TransportError   0x10) = "NoViablePath"
    show (TransportError   0x11) = "VersionNegotiationError"
    show (TransportError      x)
      | 0x100 <= x && x <= 0x01ff = case toAlertDescription $ fromIntegral (x - 0x100) of
          Just e  -> "TLS " ++ show e
          Nothing -> "TLS Alert " ++ show x
      | otherwise = "TransportError " ++ printf "%x" x
{- FOURMOLU_ENABLE -}

-- | Converting a TLS alert to a corresponding transport error.
cryptoError :: TLS.AlertDescription -> TransportError
cryptoError ad = TransportError ec
  where
    ec = 0x100 + fromIntegral (fromAlertDescription ad)

-- | Application protocol errors of QUIC.
newtype ApplicationProtocolError = ApplicationProtocolError Int
    deriving (Eq, Show)
