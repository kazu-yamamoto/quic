module Network.QUIC.Types.Queue where

import Network.QUIC.Imports
import Network.QUIC.Types.Frame
import Network.QUIC.Types.Packet
import Network.QUIC.Types.Error

data Input = InpStream StreamID ByteString
           | InpHandshake EncryptionLevel ByteString Offset Token
           | InpTransportError TransportError FrameType ReasonPhrase
           | InpApplicationError ApplicationError ReasonPhrase
           deriving Show

data Output = OutStream StreamID ByteString Offset
            | OutControl EncryptionLevel [Frame]
            | OutHndClientHello  ByteString (Maybe (StreamID,ByteString))
            | OutHndServerHello  ByteString ByteString
            | OutHndServerHelloR ByteString
            | OutHndClientFinished ByteString
            | OutHndServerNST ByteString
            deriving Show
