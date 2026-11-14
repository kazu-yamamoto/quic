module Network.QUIC.Types.Queue where

import Control.Concurrent.STM
import Control.Monad (void, when)
import Data.ByteString (ByteString)

import Network.QUIC.Types.Packet

-- | How many packets a connection may have waiting to be decrypted.
--
-- A server picks the connection a packet belongs to by the connection ID,
-- which is in the clear, and hands the packet over; whether the packet is
-- worth anything is settled later, in the receiver, by decrypting it.  So
-- anyone who knows a connection ID can make a server queue packets, and
-- they cost the sender less to send than the AEAD that rejects them costs
-- the receiver to refuse.  The queue grows, and before this it grew without
-- a limit: one connection's worth of junk could take all of a server's
-- memory.
--
-- This much is several milliseconds of a receiver's work, far more than the
-- scheduling jitter the queue is there to absorb, and each packet holds the
-- datagram it was cut from, so the queue is worth a few megabytes to a
-- sender rather than everything.
recvQLimit :: Int
recvQLimit = 4096

-- | How many bytes the packets waiting in all of a server's 'RecvQ's may
--   take together.  'recvQLimit' bounds one connection, and a server has as
--   many connections as it is asked for, so this is what bounds the server
--   (#170).  Some ten connections' worth of full queues.
recvBudgetLimit :: Int
recvBudgetLimit = 64 * 1024 * 1024

-- | Bytes in use, shared by the queues of an endpoint, and its limit.
data RecvBudget = RecvBudget Int (TVar Int)

newRecvBudget :: Int -> IO RecvBudget
newRecvBudget lim = RecvBudget lim <$> newTVarIO 0

-- | Packets, how many, their bytes, whether closed, and the budget.
data RecvQ
    = RecvQ (TQueue ReceivedPacket) (TVar Int) (TVar Int) (TVar Bool) RecvBudget

-- | The same queue.
instance Eq RecvQ where
    RecvQ q1 _ _ _ _ == RecvQ q2 _ _ _ _ = q1 == q2

newRecvQ :: RecvBudget -> IO RecvQ
newRecvQ budget =
    RecvQ
        <$> newTQueueIO
        <*> newTVarIO 0
        <*> newTVarIO 0
        <*> newTVarIO False
        <*> pure budget

readRecvQ :: RecvQ -> IO ReceivedPacket
readRecvQ (RecvQ q qlen qbytes _ (RecvBudget _ used)) = atomically $ do
    x <- readTQueue q
    let n = rpReceivedBytes x
    modifyTVar' qlen (subtract 1)
    modifyTVar' qbytes (subtract n)
    modifyTVar' used (subtract n)
    return x

-- | Queue a packet, or drop it if 'recvQLimit' are already waiting, if the
--   budget it shares with the other queues has no room for it, or if the
--   queue has been closed.
--
-- What is dropped is the packet that has just arrived rather than one
-- already queued, so that what the connection has taken on is kept and only
-- what is past the limit is lost.  A lost packet is something QUIC is built
-- to recover from.
--
-- Nothing is logged.  The only sender that can reach the limit at any rate
-- is one sending faster than the receiver can refuse what it sends, and a
-- line of log for each of those packets is the same attack by another road.
writeRecvQ :: RecvQ -> ReceivedPacket -> IO ()
writeRecvQ (RecvQ q qlen qbytes closed (RecvBudget lim used)) x = atomically $ do
    c <- readTVar closed
    n <- readTVar qlen
    u <- readTVar used
    let b = rpReceivedBytes x
    when (not c && n < recvQLimit && u + b <= lim) $ do
        writeTQueue q x
        writeTVar qlen $! n + 1
        modifyTVar' qbytes (+ b)
        writeTVar used $! u + b

-- | Put back a packet this connection had already taken.
--
-- Not subject to the limits: these come from the packets put off for want
-- of the keys to read them, which the handshake bounds, and dropping one
-- would lose a packet the connection has already accounted for.
prependRecvQ :: RecvQ -> ReceivedPacket -> STM ()
prependRecvQ (RecvQ q qlen qbytes _ (RecvBudget _ used)) x = do
    let b = rpReceivedBytes x
    unGetTQueue q x
    modifyTVar' qlen (+ 1)
    modifyTVar' qbytes (+ b)
    modifyTVar' used (+ b)

-- | Closing a queue nobody will read again: what it holds goes back to the
--   budget, and what is written to it from now on is dropped.  A queue the
--   dispatcher can still find, for a connection that has ended, would
--   otherwise hold its share of the budget for good.
closeRecvQ :: RecvQ -> IO ()
closeRecvQ (RecvQ q qlen qbytes closed (RecvBudget _ used)) = atomically $ do
    writeTVar closed True
    b <- readTVar qbytes
    modifyTVar' used (subtract b)
    writeTVar qbytes 0
    writeTVar qlen 0
    void $ flushTQueue q

----------------------------------------------------------------

-- | How many DATAGRAM frames a connection may have waiting for the
--   application.  Each fits in a packet, so this is a megabyte and a half
--   or so (#226).
datagramQLimit :: Int
datagramQLimit = 1024

data DatagramQ = DatagramQ (TQueue ByteString) (TVar Int)

newDatagramQ :: IO DatagramQ
newDatagramQ = DatagramQ <$> newTQueueIO <*> newTVarIO 0

readDatagramQSTM :: DatagramQ -> STM ByteString
readDatagramQSTM (DatagramQ q qlen) = do
    x <- readTQueue q
    modifyTVar' qlen (subtract 1)
    return x

flushDatagramQSTM :: DatagramQ -> STM [ByteString]
flushDatagramQSTM (DatagramQ q qlen) = do
    writeTVar qlen 0
    flushTQueue q

-- | Queue a DATAGRAM, or drop it if 'datagramQLimit' are already waiting.
--   RFC 9221 Sec 5 lets a receiver drop DATAGRAM frames.
writeDatagramQ :: DatagramQ -> ByteString -> IO ()
writeDatagramQ (DatagramQ q qlen) x = atomically $ do
    n <- readTVar qlen
    when (n < datagramQLimit) $ do
        writeTQueue q x
        writeTVar qlen $! n + 1
