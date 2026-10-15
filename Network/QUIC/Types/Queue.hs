module Network.QUIC.Types.Queue where

import Control.Concurrent.STM
import Control.Monad (when)

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

data RecvQ = RecvQ (TQueue ReceivedPacket) (TVar Int)

newRecvQ :: IO RecvQ
newRecvQ = RecvQ <$> newTQueueIO <*> newTVarIO 0

readRecvQ :: RecvQ -> IO ReceivedPacket
readRecvQ (RecvQ q qlen) = atomically $ do
    x <- readTQueue q
    modifyTVar' qlen (subtract 1)
    return x

-- | Queue a packet, or drop it if 'recvQLimit' are already waiting.
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
writeRecvQ (RecvQ q qlen) x = atomically $ do
    n <- readTVar qlen
    when (n < recvQLimit) $ do
        writeTQueue q x
        writeTVar qlen $! n + 1

-- | Put back a packet this connection had already taken.
--
-- Not subject to the limit: these come from the packets put off for want of
-- the keys to read them, which the handshake bounds, and dropping one would
-- lose a packet the connection has already accounted for.
prependRecvQ :: RecvQ -> ReceivedPacket -> STM ()
prependRecvQ (RecvQ q qlen) x = do
    unGetTQueue q x
    modifyTVar' qlen (+ 1)
