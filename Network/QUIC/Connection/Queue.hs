module Network.QUIC.Connection.Queue where

import Control.Concurrent.STM

import Network.QUIC.Types
import Network.QUIC.Connection.Types

takeInput :: Connection -> IO Input
takeInput conn = atomically $ readTQueue (inputQ conn)

putInput :: Connection -> Input -> IO ()
putInput conn inp = atomically $ writeTQueue (inputQ conn) inp

takeCrypto :: Connection -> IO Input
takeCrypto conn = atomically $ readTQueue (cryptoQ conn)

putCrypto :: Connection -> Input -> IO ()
putCrypto conn inp = atomically $ writeTQueue (cryptoQ conn) inp

takeOutput :: Connection -> IO Output
takeOutput conn = atomically $ readTQueue (outputQ conn)

putOutput :: Connection -> Output -> IO ()
putOutput conn out = atomically $ writeTQueue (outputQ conn) out

putOutput' :: OutputQ -> Output -> IO ()
putOutput' outQ out = atomically $ writeTQueue outQ out

putOutputPP :: Connection -> (PlainPacket,[PacketNumber]) -> IO ()
putOutputPP conn (ppkt,pns) = atomically $ writeTQueue (outputQ conn) $ OutPlainPacket ppkt pns

