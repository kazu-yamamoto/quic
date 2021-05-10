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

----------------------------------------------------------------

takeSendStreamQ :: Connection -> IO TxStreamData
takeSendStreamQ conn = atomically $ readTQueue $ sharedSendStreamQ $ shared conn

takeSendStreamQSTM :: Connection -> STM TxStreamData
takeSendStreamQSTM conn = readTQueue $ sharedSendStreamQ $ shared conn

tryPeekSendStreamQ :: Connection -> IO (Maybe TxStreamData)
tryPeekSendStreamQ conn = atomically $ tryPeekTQueue $ sharedSendStreamQ $ shared conn

putSendStreamQ :: Connection -> TxStreamData -> IO ()
putSendStreamQ conn out = atomically $ writeTQueue (sharedSendStreamQ $ shared conn) out

----------------------------------------------------------------

readMigrationQ :: Connection -> IO ReceivedPacket
readMigrationQ conn = atomically $ readTQueue $ migrationQ conn

writeMigrationQ :: Connection -> ReceivedPacket -> IO ()
writeMigrationQ conn x = atomically $ writeTQueue (migrationQ conn) x
