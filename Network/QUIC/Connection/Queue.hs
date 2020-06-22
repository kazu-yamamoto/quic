module Network.QUIC.Connection.Queue where

import Control.Concurrent.STM

import Network.QUIC.Connection.Types
import Network.QUIC.Stream
import Network.QUIC.Types

takeInput :: Connection -> IO Input
takeInput conn = atomically $ readTQueue (inputQ conn)

putInput :: Connection -> Input -> IO ()
putInput conn inp = atomically $ writeTQueue (inputQ conn) inp

takeCrypto :: Connection -> IO Crypto
takeCrypto conn = atomically $ readTQueue (cryptoQ conn)

putCrypto :: Connection -> Crypto -> IO ()
putCrypto conn inp = atomically $ writeTQueue (cryptoQ conn) inp

takeOutputSTM :: Connection -> STM Output
takeOutputSTM conn = readTQueue (outputQ conn)

tryPeekOutput :: Connection -> IO (Maybe Output)
tryPeekOutput conn = atomically $ tryPeekTQueue (outputQ conn)

putOutput :: Connection -> Output -> IO ()
putOutput conn out = atomically $ writeTQueue (outputQ conn) out

putOutputPP :: Connection -> PlainPacket -> IO ()
putOutputPP conn ppkt = atomically $ writeTQueue (outputQ conn) $ OutRetrans ppkt

takeSendStreamQSTM :: Connection -> STM TxStreamData
takeSendStreamQSTM conn = readTBQueue $ sharedSendStreamQ $ shared conn

