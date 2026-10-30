{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Closer (closure) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Control.Exception as E
import Data.Either (isRight)
import Foreign.Marshal.Alloc
import Foreign.Ptr
import qualified Network.Socket as NS

import Network.QUIC.Common
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Packet
import Network.QUIC.Recovery
import Network.QUIC.Sender
import Network.QUIC.Types

closure :: Connection -> LDCC -> Either E.SomeException a -> IO a
closure conn ldcc (Right x) = do
    closure' conn ldcc $ ConnectionClose NoError 0 ""
    return x
closure conn ldcc (Left se)
    | Just e@(TransportErrorIsSent err desc) <- E.fromException se = do
        closure' conn ldcc $ ConnectionClose err 0 desc
        E.throwIO e
    | Just e@(ApplicationProtocolErrorIsSent err desc) <- E.fromException se = do
        closure' conn ldcc $ ConnectionCloseApp err desc
        E.throwIO e
    | Just (Abort err desc) <- E.fromException se = do
        closure' conn ldcc $ ConnectionCloseApp err desc
        E.throwIO $ ApplicationProtocolErrorIsSent err desc
    | Just (VerNego vers) <- E.fromException se = do
        E.throwIO $ NextVersion vers
    -- Nothing to say: the connection is over for a reason the peer knows at
    -- least as well as we do.  An idle timeout is closed in silence (RFC 9000
    -- Sec 10.1); the rest are the peer having closed, or told us to stop.
    | isOver se = E.throwIO se
    -- Asynchronous, so we are the ones being taken down, and whoever is doing
    -- it says what happens next.  'run' has 'sendFinal' for its own ending.
    | isAsyncException se = E.throwIO se
    -- Anything else went wrong in here.  RFC 9000 Sec 10.2: an endpoint that
    -- ends a connection sends CONNECTION_CLOSE.  Without one the peer is left
    -- talking to a connection that is gone until its own idle timeout, or
    -- until a Stateless Reset reaches it -- which, for a server, is a second
    -- away, since the dispatcher holds a dead connection's IDs that long.
    --
    -- The reason phrase says nothing of what it was.  It goes to the peer,
    -- and what went wrong in here is our business; the debug log has it.
    | otherwise = do
        closure' conn ldcc $ ConnectionClose InternalError 0 "internal error"
        E.throwIO se
  where
    isOver e = case E.fromException e of
        Just (ConnectionIsClosed _) -> True
        Just (ConnectionIsTimeout _) -> True
        Just ConnectionIsReset -> True
        Just (TransportErrorIsReceived _ _) -> True
        Just (ApplicationProtocolErrorIsReceived _ _) -> True
        _ -> False

-- | Telling the peer the connection is over, once.
--
-- Once, because it is said at the first place that knows: where the protocol
-- threads have finished and the application has not.  What comes here after
-- that is the same ending on its way out, and the peer has heard it.
closure' :: Connection -> LDCC -> Frame -> IO ()
closure' conn ldcc frame = do
    already <- atomicModifyIORef' (connCloseSent conn) $ \b -> (True, b)
    unless already $ closure'' conn ldcc frame

closure'' :: Connection -> LDCC -> Frame -> IO ()
closure'' conn ldcc frame = do
    sock <- getSocket conn
    peersa <- peerSockAddr <$> getPathInfo conn
    connected <- getSockConnected conn
    -- send
    let bufsiz = maximumUdpPayloadSize
    -- Both buffers are taken before anything that can throw, and one action
    -- frees them.  They used to be taken either side of 'encodeCC' and
    -- 'killReaders' with nothing to free them if those threw, and this runs
    -- on the way out of every connection.
    sendbuf <- mallocBytes bufsiz
    mrecvbuf <-
        if isServer conn
            then return Nothing
            else Just <$> mallocBytes bufsiz `E.onException` free sendbuf
    let freeBufs = free sendbuf >> mapM_ free mrecvbuf
    flip E.onException freeBufs $ do
        -- This must be called before freeResourcesin runClient.
        siz <- encodeCC conn sendbuf bufsiz frame
        let send
                | connected = void $ NS.sendBuf sock sendbuf siz
                | otherwise = void $ NS.sendBufTo sock sendbuf siz peersa
        -- recv and clos
        killReaders conn -- client only
        let (recvWithin, clos) = case mrecvbuf of
                Nothing ->
                    -- The server reads its datagrams from a queue, not from
                    -- a socket, and a timeout does reach a thread waiting
                    -- on one.
                    ( \tmo -> isJust <$> timeout tmo "closer" (void $ connRecv conn)
                    , return ()
                    )
                Just recvbuf ->
                    -- The deadline is waited for beside the receive rather
                    -- than thrown at it: an asynchronous exception does not
                    -- reach a thread blocked in a socket call on Windows.
                    -- Nothing is abandoned, so nothing has to be closed to
                    -- end it either.
                    let recv' (Microseconds us) = do
                            expired <- registerDelay us
                            let giveUp = check =<< readTVar expired
                                again = recv' (Microseconds us)
                            if connected
                                then isRight <$> NS.recvBufWith sock recvbuf bufsiz giveUp
                                else do
                                    r <- NS.recvBufFromWith sock recvbuf bufsiz giveUp
                                    case r of
                                        Left () -> return False
                                        Right (_, sa)
                                            | sa /= peersa -> again
                                            | otherwise -> return True
                        -- 'killReaders' above has seen the readers out,
                        -- and this runs on the way out of the closer, the
                        -- last thread to send or receive on it: @close(2)@
                        -- is enough.
                        clos' = do
                            NS.unsafeClose sock
                            -- This is just in case.
                            getSocket conn >>= NS.unsafeClose
                     in (recv', clos')
        -- hook
        let hook = onCloseCompleted $ connHooks conn
        pto <- getPTO ldcc
        -- The first one goes out here, in the thread that is ending the
        -- connection, rather than in the closer below: a server that is
        -- stopping lets go of its sockets as soon as its connections have
        -- ended, and a CONNECTION_CLOSE still waiting its turn on a thread
        -- of its own misses them.  The closer repeats it for a peer that
        -- did not hear it, which is what it is for.
        send
        void $ forkFinally (closer conn pto send recvWithin hook) $ \e -> do
            case e of
                Left e' -> connDebugLog conn $ "closure' " <> bhow e'
                Right _ -> return ()
            freeBufs
            clos

encodeCC :: Connection -> Buffer -> BufferSize -> Frame -> IO Int
encodeCC conn sendbuf0 bufsiz0 frame = do
    lvl0 <- getEncryptionLevel conn
    let lvl
            | lvl0 == RTT0Level = InitialLevel
            | otherwise = lvl0
    if lvl == HandshakeLevel
        then do
            siz0 <- encCC sendbuf0 bufsiz0 InitialLevel
            let sendbuf1 = sendbuf0 `plusPtr` siz0
                bufsiz1 = bufsiz0 - siz0
            siz1 <- encCC sendbuf1 bufsiz1 HandshakeLevel
            return (siz0 + siz1)
        else
            encCC sendbuf0 bufsiz0 lvl
  where
    encCC sendbuf bufsiz lvl = do
        header <- mkHeader conn lvl
        mypn <- nextPacketNumber conn
        let plain = Plain (Flags 0) mypn [frame] 0
            ppkt = PlainPacket header plain
            res = SizedBuffer sendbuf bufsiz
        siz <- fst <$> encodePlainPacket conn res ppkt Nothing
        if siz >= 0
            then do
                now <- getTimeMicrosecond
                qlogSent conn ppkt now
                return siz
            else
                return 0

-- The fourth argument receives a datagram within the given time,
-- answering 'False' if none came.
closer
    :: Connection
    -> Microseconds
    -> IO ()
    -> (Microseconds -> IO Bool)
    -> IO ()
    -> IO ()
closer _conn (Microseconds pto) send recvWithin hook = do
    labelMe "QUIC closer"
    loop (3 :: Int)
  where
    loop 0 = return ()
    loop n = do
        send
        getTimeMicrosecond >>= skip (Microseconds pto)
        got <- recvWithin $ Microseconds (pto !>>. 1)
        if got then loop (n - 1) else hook
    skip tmo@(Microseconds duration) base = do
        got <- recvWithin tmo
        when got $ do
            Microseconds elapsed <- getElapsedTimeMicrosecond base
            let duration' = duration - elapsed
            when (duration' >= 5000) $ skip (Microseconds duration') base
