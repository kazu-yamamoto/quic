module Network.QUIC.Types.UserError where

import qualified Control.Exception as E
import qualified Network.TLS as TLS

import Network.QUIC.Imports
import Network.QUIC.Types.Error
import Network.QUIC.Types.Frame
import Network.QUIC.Types.Packet

data QUICError = VersionIsUnknown Word32
               | TransportErrorIsSent     TransportError ReasonPhrase
               | TransportErrorIsReceived TransportError ReasonPhrase
               | ApplicationErrorIsSent     ApplicationError ReasonPhrase
               | ApplicationErrorIsReceived ApplicationError ReasonPhrase
               | ConnectionIsClosed
               | ConnectionIsTimeout
               | ConnectionIsReset
               | StreamIsClosed
               | HandshakeFailed TLS.AlertDescription -- failed in my side
               | NoVersionIsSpecified
               | VersionNegotiationFailed
               | BadThingHappen E.SomeException
               deriving (Show)

instance E.Exception QUICError

data InternalControl = NextVersion Version
                     | MustNotReached
                     deriving (Eq, Show)

instance E.Exception InternalControl
