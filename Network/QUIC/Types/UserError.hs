module Network.QUIC.Types.UserError where

import qualified Control.Exception as E

import Network.QUIC.Imports
import Network.QUIC.Types.Error
import Network.QUIC.Types.Packet

data QUICError = PacketCannotBeDecrypted
               | VersionIsUnknown Word32
               | TransportErrorOccurs TransportError ReasonPhrase
               | ApplicationErrorOccurs ApplicationError ReasonPhrase
               | ConnectionIsClosed
               | ConnectionIsNotOpen
               | HandshakeFailed String
               | NoVersionIsSpecified
               | VersionNegotiationFailed
               | NextVersion Version
               | BadThingHappen E.SomeException
               | MustNotReached
               deriving (Show)

instance E.Exception QUICError
