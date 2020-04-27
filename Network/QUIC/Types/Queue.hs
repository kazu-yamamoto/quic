module Network.QUIC.Types.Queue where

import Control.Concurrent.STM

import Network.QUIC.Types.Packet

newtype RecvQ = RecvQ (TQueue CryptPacket)

newRecvQ :: IO RecvQ
newRecvQ = RecvQ <$> newTQueueIO

readRecvQ :: RecvQ -> IO CryptPacket
readRecvQ (RecvQ q) = atomically $ readTQueue q

writeRecvQ :: RecvQ -> CryptPacket -> IO ()
writeRecvQ (RecvQ q) x = atomically $ writeTQueue q x

prependRecvQ :: RecvQ -> CryptPacket -> STM ()
prependRecvQ (RecvQ q) = unGetTQueue q
