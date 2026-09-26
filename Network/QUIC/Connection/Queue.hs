module Network.QUIC.Connection.Queue where

import Control.Concurrent.STM
import Network.Control (getRate)

import Network.QUIC.Connection.Types
import Network.QUIC.Stream
import Network.QUIC.Types

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

-- | Take the oldest queued retransmission at this level, leaving the rest of
-- the queue in order.
--
-- A PTO probe may be sent past a full congestion window, and this is how it
-- reaches the packet that needs sending.  Once a packet has been declared
-- lost it is no longer in the sent-packet database, so 'releaseOldest' cannot
-- find it; it is here, waiting for a window that may not open until it has
-- gone out.
takeRetransSTM :: Connection -> EncryptionLevel -> STM (Maybe PlainPacket)
takeRetransSTM conn lvl = do
    outs <- flushTQueue (outputQ conn)
    let (found, rest) = pick outs
    mapM_ (writeTQueue (outputQ conn)) rest
    return found
  where
    pick [] = (Nothing, [])
    pick (o@(OutRetrans ppkt@(PlainPacket hdr _)) : os)
        | levelOf hdr == lvl = (Just ppkt, os)
        | otherwise = let (f, r) = pick os in (f, o : r)
    pick (o : os) = let (f, r) = pick os in (f, o : r)
    levelOf hdr
        | l == RTT0Level = RTT1Level
        | otherwise = l
      where
        l = packetEncryptionLevel hdr

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

----------------------------------------------------------------

outputLimit :: Int
outputLimit = 10

rateOK :: Connection -> IO Bool
rateOK conn = do
    rate <- getRate $ outputRate conn
    return $ rate < outputLimit
