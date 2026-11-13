module Network.QUIC.Connection.Queue where

import Control.Concurrent.STM

import Network.QUIC.Connection.Types
import Network.QUIC.Recovery (StreamResets)
import Network.QUIC.Stream
import Network.QUIC.Types

----------------------------------------------------------------

takeInput :: Connection -> IO Input
takeInput conn = atomically $ readTQueue (inputQ conn) `orElse` peerClosedSTM conn

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
takeOutputSTM conn = do
    out <- readTQueue (outputQ conn)
    modifyTVar' (queuedControls conn) (subtract $ countControls out)
    return out

tryTakeOutput :: Connection -> IO (Maybe Output)
tryTakeOutput conn = atomically $ do
    mout <- tryReadTQueue (outputQ conn)
    case mout of
        Nothing -> return ()
        Just out -> modifyTVar' (queuedControls conn) (subtract $ countControls out)
    return mout

tryPeekOutput :: Connection -> IO (Maybe Output)
tryPeekOutput conn = atomically $ tryPeekTQueue (outputQ conn)

putOutput :: Connection -> Output -> IO ()
putOutput conn out = atomically $ do
    writeTQueue (outputQ conn) out
    modifyTVar' (queuedControls conn) (+ countControls out)

-- | Control frames waiting for the sender, which a peer that keeps the
--   congestion window shut can make us pile up (CVE-2024-22189).
getQueuedControls :: Connection -> IO Int
getQueuedControls conn = readTVarIO $ queuedControls conn

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
takeRetransSTM
    :: Connection -> EncryptionLevel -> STM (Maybe (PlainPacket, StreamResets))
takeRetransSTM conn lvl = do
    outs <- flushTQueue (outputQ conn)
    let (found, rest) = pick outs
    mapM_ (writeTQueue (outputQ conn)) rest
    case found of
        Nothing -> return ()
        Just (ppkt, resets) ->
            modifyTVar' (queuedControls conn) $
                subtract $
                    countControls $
                        OutRetrans ppkt resets
    return found
  where
    pick [] = (Nothing, [])
    pick (o@(OutRetrans ppkt@(PlainPacket hdr _) resets) : os)
        | levelOf hdr == lvl = (Just (ppkt, resets), os)
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

putSendStreamQSTM :: Connection -> TxStreamData -> STM ()
putSendStreamQSTM conn = writeTQueue (sharedSendStreamQ $ shared conn)

putSendStreamQ :: Connection -> TxStreamData -> IO ()
putSendStreamQ conn out = atomically $ writeTQueue (sharedSendStreamQ $ shared conn) out

isEmptyStreamSTM :: Connection -> STM Bool
isEmptyStreamSTM conn = isEmptyTQueue $ sharedSendStreamQ $ shared conn
