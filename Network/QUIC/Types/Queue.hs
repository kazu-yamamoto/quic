module Network.QUIC.Types.Queue where

import Control.Concurrent.STM

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.Error
import Network.QUIC.Types.Frame
import Network.QUIC.Types.Packet
import Network.QUIC.Types.UserError

data Input = InpStream StreamId ByteString Fin
           | InpHandshake EncryptionLevel ByteString
           | InpTransportError TransportError FrameType ReasonPhrase
           | InpApplicationError ApplicationError ReasonPhrase
           | InpVersion (Maybe Version)
           | InpError QUICError
           deriving Show

data Output = OutStream StreamId ByteString Fin
            | OutShutdown StreamId
            | OutControl EncryptionLevel [Frame]
            | OutHndClientHello  ByteString (Maybe (StreamId,ByteString))
            | OutHndServerHello  ByteString ByteString
            | OutHndServerHelloR ByteString
            | OutHndClientFinished ByteString
            | OutHndServerNST ByteString
            | OutPlainPacket PlainPacket [PacketNumber]
            deriving Show

newtype RecvQ = RecvQ (TQueue CryptPacket)

newRecvQ :: IO RecvQ
newRecvQ = RecvQ <$> newTQueueIO

readRecvQ :: RecvQ -> IO CryptPacket
readRecvQ (RecvQ q) = atomically $ readTQueue q

writeRecvQ :: RecvQ -> CryptPacket -> IO ()
writeRecvQ (RecvQ q) x = atomically $ writeTQueue q x
