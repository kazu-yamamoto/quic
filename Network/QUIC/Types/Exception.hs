module Network.QUIC.Types.Exception where

import qualified Network.TLS as TLS
import qualified UnliftIO.Exception as E

import Network.QUIC.Imports
import Network.QUIC.Types.Error
import Network.QUIC.Types.Frame
import Network.QUIC.Types.Packet

-- | User level exceptions for QUIC.
data QUICException =
    ConnectionIsClosed -- NoError
  | TransportErrorIsReceived TransportError ReasonPhrase
  | TransportErrorIsSent     TransportError ReasonPhrase
  | ApplicationProtocolErrorIsReceived ApplicationProtocolError ReasonPhrase
  | ApplicationProtocolErrorIsSent     ApplicationProtocolError ReasonPhrase
  | ConnectionIsTimeout
  | ConnectionIsReset
  | StreamIsClosed
  | HandshakeFailed TLS.AlertDescription -- failed in my side
  | VersionIsUnknown Word32
  | NoVersionIsSpecified
  | VersionNegotiationFailed
  | BadThingHappen E.SomeException
  deriving (Show)

instance E.Exception QUICException

data InternalControl = MustNotReached
                     | ExitConnection
                     | WrongTransportParameter
                     | BreakForever
                     deriving (Eq, Show)

instance E.Exception InternalControl

newtype NextVersion = NextVersion [Version] deriving (Show)

instance E.Exception NextVersion

data Abort = Abort ApplicationProtocolError ReasonPhrase
           | VerNego [Version]
           deriving (Show)

instance E.Exception Abort where
  fromException = E.asyncExceptionFromException
  toException = E.asyncExceptionToException
