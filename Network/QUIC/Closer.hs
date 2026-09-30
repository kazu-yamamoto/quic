{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Closer (closure) where

import Control.Concurrent
import qualified Control.Exception as E
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
    sendbuf <- mallocBytes bufsiz
    -- This must be called before freeResourcesin runClient.
    siz <- encodeCC conn sendbuf bufsiz frame
    -- Nothing came out, so there is nothing to send.  'encodeCC' answers 0
    -- when the keys for the level it chose are gone, and it says so only by
    -- way of the qlog line it does not write; what went out was an empty
    -- datagram, which tells the peer nothing and leaves no trace either.
    when (siz <= 0) $ do
        lvl <- getEncryptionLevel conn
        connDebugLog conn $
            "closure: no CONNECTION_CLOSE to send at " <> bhow lvl <> "; the keys are gone"
    let send
            | siz <= 0 = return ()
            | connected = void $ NS.sendBuf sock sendbuf siz
            | otherwise = void $ NS.sendBufTo sock sendbuf siz peersa
    -- recv and clos
    killReaders conn -- client only
    (recv, freeRecvBuf, clos) <-
        if isServer conn
            then return (void $ connRecv conn, free sendbuf, return ())
            else do
                recvbuf <- mallocBytes bufsiz
                let recv'
                        | connected = void $ NS.recvBuf sock recvbuf bufsiz
                        | otherwise = do
                            (_, sa) <- NS.recvBufFrom sock recvbuf bufsiz
                            when (sa /= peersa) recv'
                    free' = free recvbuf >> free sendbuf
                    clos' = do
                        NS.close sock
                        -- This is just in case.
                        getSocket conn >>= NS.close
                return (recv', free', clos')
    -- hook
    let hook = onCloseCompleted $ connHooks conn
    pto <- getPTO ldcc
    void $ forkFinally (closer conn pto send recv hook) $ \e -> do
        case e of
            Left e' -> connDebugLog conn $ "closure' " <> bhow e'
            Right _ -> return ()
        freeRecvBuf
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

closer :: Connection -> Microseconds -> IO () -> IO () -> IO () -> IO ()
closer _conn (Microseconds pto) send recv hook = do
    labelMe "QUIC closer"
    loop (3 :: Int)
  where
    loop 0 = return ()
    loop n = do
        send
        getTimeMicrosecond >>= skip (Microseconds pto)
        mx <- timeout (Microseconds (pto !>>. 1)) "closer 1" recv
        case mx of
            Nothing -> hook
            Just () -> loop (n - 1)
    skip tmo@(Microseconds duration) base = do
        mx <- timeout tmo "closer 2" recv
        case mx of
            Nothing -> return ()
            Just () -> do
                Microseconds elapsed <- getElapsedTimeMicrosecond base
                let duration' = duration - elapsed
                when (duration' >= 5000) $ skip (Microseconds duration') base
