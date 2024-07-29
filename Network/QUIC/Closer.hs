{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Closer (closure) where

import Foreign.Marshal.Alloc
import Foreign.Ptr
import qualified Network.Socket as NS
import UnliftIO.Concurrent
import qualified UnliftIO.Exception as E

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
    | otherwise = E.throwIO se

closure' :: Connection -> LDCC -> Frame -> IO ()
closure' conn ldcc frame = do
    sock <- getSocket conn
    peersa <- getPeerSockAddr conn
    -- send
    let sbuf@(SizedBuffer sendBuf _) = encryptRes conn
    siz <- encodeCC conn sbuf frame
    let send = void $ NS.sendBufTo sock sendBuf siz peersa
    -- recv and clos
    killReaders conn -- client only
    (recv, freeRecvBuf, clos) <-
        if isServer conn
            then return (void $ connRecv conn, return (), return ())
            else do
                let bufsiz = maximumUdpPayloadSize
                recvBuf <- mallocBytes bufsiz
                let recv' = void $ NS.recvBuf sock recvBuf bufsiz
                    free' = free recvBuf
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

encodeCC :: Connection -> SizedBuffer -> Frame -> IO Int
encodeCC conn res0@(SizedBuffer sendBuf0 bufsiz0) frame = do
    lvl0 <- getEncryptionLevel conn
    let lvl
            | lvl0 == RTT0Level = InitialLevel
            | otherwise = lvl0
    if lvl == HandshakeLevel
        then do
            siz0 <- encCC res0 InitialLevel
            let sendBuf1 = sendBuf0 `plusPtr` siz0
                bufsiz1 = bufsiz0 - siz0
                res1 = SizedBuffer sendBuf1 bufsiz1
            siz1 <- encCC res1 HandshakeLevel
            return (siz0 + siz1)
        else
            encCC res0 lvl
  where
    encCC res lvl = do
        header <- mkHeader conn lvl
        mypn <- nextPacketNumber conn
        let plain = Plain (Flags 0) mypn [frame] 0
            ppkt = PlainPacket header plain
        siz <- fst <$> encodePlainPacket conn res ppkt Nothing
        if siz >= 0
            then do
                now <- getTimeMicrosecond
                qlogSent conn ppkt now
                return siz
            else
                return 0

closer :: Connection -> Microseconds -> IO () -> IO () -> IO () -> IO ()
closer _conn (Microseconds pto) send recv hook = loop (3 :: Int)
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
