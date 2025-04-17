module Network.QUIC.Connection.Queue where

import Control.Concurrent.STM

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Stream

----------------------------------------------------------------

takeInput :: Connection -> IO Input
takeInput conn = atomically $ readTQueue (inputQ conn)

putInput :: Connection -> Input -> IO ()
putInput conn inp = atomically $ writeTQueue (inputQ conn) inp

----------------------------------------------------------------

takeCrypto :: Connection -> IO Crypto
takeCrypto conn = atomically $ readTQueue (cryptoQ conn)

putCrypto :: Connection -> Crypto -> IO ()
putCrypto conn inp = atomically $ writeTQueue (cryptoQ conn) inp

isEmptyCryptoSTM :: Connection -> STM Bool
isEmptyCryptoSTM conn = isEmptyTQueue $ cryptoQ conn

----------------------------------------------------------------

takeOutputSTM :: Connection -> STM Output
takeOutputSTM conn = readTQueue (outputQ conn)

tryTakeOutput :: Connection -> IO (Maybe Output)
tryTakeOutput conn = atomically $ tryReadTQueue (outputQ conn)

tryPeekOutput :: Connection -> IO (Maybe Output)
tryPeekOutput conn = atomically $ tryPeekTQueue (outputQ conn)

putOutput :: Connection -> Output -> IO ()
putOutput conn out = atomically $ writeTQueue (outputQ conn) out

isEmptyOutputSTM :: Connection -> STM Bool
isEmptyOutputSTM conn = isEmptyTQueue $ outputQ conn

----------------------------------------------------------------

outputLimit :: Int
outputLimit = 10

putOutputLim :: Connection -> Output -> IO ()
putOutputLim conn out = atomically $ do
    len <- fromIntegral <$> lengthTBQueue (outputQLim conn)
    -- unless ok, the frames are intentionally dropped.
    when (len < outputLimit) $ writeTBQueue (outputQLim conn) out

takeOutputLimSTM :: Connection -> STM Output
takeOutputLimSTM conn = readTBQueue (outputQLim conn)

isEmptyOutputLimSTM :: Connection -> STM Bool
isEmptyOutputLimSTM conn = isEmptyTBQueue $ outputQLim conn

----------------------------------------------------------------

takeSendStreamQ :: Connection -> IO TxStreamData
takeSendStreamQ conn = atomically $ readTQueue $ sharedSendStreamQ $ shared conn

takeSendStreamQSTM :: Connection -> STM TxStreamData
takeSendStreamQSTM conn = readTQueue $ sharedSendStreamQ $ shared conn

tryPeekSendStreamQ :: Connection -> IO (Maybe TxStreamData)
tryPeekSendStreamQ conn = atomically $ tryPeekTQueue $ sharedSendStreamQ $ shared conn

putSendStreamQ :: Connection -> TxStreamData -> IO ()
putSendStreamQ conn out = atomically $ writeTQueue (sharedSendStreamQ $ shared conn) out

isEmptyStreamSTM :: Connection -> STM Bool
isEmptyStreamSTM conn = isEmptyTQueue $ sharedSendStreamQ $ shared conn
