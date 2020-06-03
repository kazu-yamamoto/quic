module Network.QUIC.Connection.Queue where

import Control.Concurrent.STM

import Network.QUIC.Connection.Types
import Network.QUIC.Stream
import Network.QUIC.Types

takeInput :: Connection -> IO Input
takeInput conn = atomically $ readTQueue (inputQ conn)

putInput :: Connection -> Input -> IO ()
putInput conn inp = atomically $ writeTQueue (inputQ conn) inp

takeCrypto :: Connection -> IO Input
takeCrypto conn = atomically $ readTQueue (cryptoQ conn)

putCrypto :: Connection -> Input -> IO ()
putCrypto conn inp = atomically $ writeTQueue (cryptoQ conn) inp

takeOutputSTM :: Connection -> STM Output
takeOutputSTM conn = readTQueue (outputQ conn)

tryPeekOutput :: Connection -> IO (Maybe Output)
tryPeekOutput conn = atomically $ tryPeekTQueue (outputQ conn)

putOutput :: Connection -> Output -> IO ()
putOutput conn out = atomically $ writeTQueue (outputQ conn) out

putOutputPP :: Connection -> PlainPacket -> IO ()
putOutputPP conn ppkt = atomically $ writeTQueue (outputQ conn) $ OutPlainPacket ppkt

takeTxStreamData :: Stream -> IO TxStreamData
takeTxStreamData strm = atomically $ readTBQueue $ sharedTxStreamDataQ $ streamShared strm

takeTxStreamDataSTM :: Connection -> STM TxStreamData
takeTxStreamDataSTM conn = readTBQueue $ sharedTxStreamDataQ $ shared conn

tryPeekTxStreamData :: Stream -> IO (Maybe TxStreamData)
tryPeekTxStreamData strm = atomically $ tryPeekTBQueue $ sharedTxStreamDataQ $ streamShared strm

putTxStreamData :: Stream -> TxStreamData -> IO ()
putTxStreamData strm out = atomically $ writeTBQueue (sharedTxStreamDataQ $ streamShared strm) out
