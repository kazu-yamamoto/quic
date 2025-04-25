module Network.QUIC.Types.Exception where

import qualified Control.Exception as E
import qualified Network.TLS as TLS

import Network.QUIC.Imports
import Network.QUIC.Types.Error
import Network.QUIC.Types.Frame
import Network.QUIC.Types.Packet

-- | User level exceptions for QUIC.
data QUICException
    = ConnectionIsClosed ReasonPhrase
    | TransportErrorIsReceived TransportError ReasonPhrase
    | TransportErrorIsSent TransportError ReasonPhrase
    | ApplicationProtocolErrorIsReceived ApplicationProtocolError ReasonPhrase
    | ApplicationProtocolErrorIsSent ApplicationProtocolError ReasonPhrase
    | ConnectionIsTimeout String
    | ConnectionIsReset
    | StreamIsClosed
    | HandshakeFailed TLS.AlertDescription -- failed in my side
    | VersionIsUnknown Word32
    | NoVersionIsSpecified
    | VersionNegotiationFailed
    | BadThingHappen E.SomeException
    deriving (Show)

instance E.Exception QUICException

data InternalControl
    = MustNotReached
    | ExitConnection
    | WrongTransportParameter
    | WrongVersionInformation
    | BreakForever
    deriving (Eq, Show)

instance E.Exception InternalControl

newtype NextVersion = NextVersion VersionInfo deriving (Show)

instance E.Exception NextVersion

data Abort
    = Abort ApplicationProtocolError ReasonPhrase
    | VerNego VersionInfo
    deriving (Show)

instance E.Exception Abort where
    fromException = E.asyncExceptionFromException
    toException = E.asyncExceptionToException
