{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Closer (closure) where

import Foreign.Marshal.Alloc
import qualified Network.Socket as NS
import UnliftIO.Concurrent
import qualified UnliftIO.Exception as E
import Foreign.Ptr

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Recovery
import Network.QUIC.Sender
import Network.QUIC.Types

closure :: Connection -> LDCC -> Either QUICException (Either () a) -> IO a
closure _    _    (Right (Left ())) = E.throwIO MustNotReached
closure conn ldcc (Right (Right x)) = do
    closure' conn ldcc $ ConnectionClose NoError 0 ""
    return x
closure conn ldcc (Left e@(TransportErrorIsSent err desc)) = do
    closure' conn ldcc $ ConnectionClose err 0 desc
    E.throwIO e
closure conn ldcc (Left e@(ApplicationProtocolErrorIsSent err desc)) = do
    closure' conn ldcc $ ConnectionCloseApp err desc
    E.throwIO e
closure _    _    (Left e) = E.throwIO e

closure' :: Connection -> LDCC -> Frame -> IO ()
closure' conn ldcc frame = do
    killReaders conn
    killTimeouter <- replaceKillTimeouter conn
    socks@(s:_) <- clearSockets conn
    let bufsiz = maximumUdpPayloadSize
    sendBuf <- mallocBytes (bufsiz * 3)
    siz <- encodeCC conn frame sendBuf bufsiz
    let recvBuf = sendBuf `plusPtr` (bufsiz * 2)
        recv = NS.recvBuf s recvBuf bufsiz
        send = NS.sendBuf s sendBuf siz
        hook = onCloseCompleted $ connHooks conn
    pto <- getPTO ldcc
    void $ forkFinally (closer pto send recv hook) $ \_ -> do
        free sendBuf
        mapM_ NS.close socks
        killTimeouter

encodeCC :: Connection -> Frame -> Buffer -> BufferSize -> IO Int
encodeCC conn frame sendBuf0 bufsiz0 = do
    lvl0 <- getEncryptionLevel conn
    let lvl | lvl0 == RTT0Level = InitialLevel
            | otherwise         = lvl0
    if lvl == HandshakeLevel then do
        siz0 <- encCC sendBuf0 bufsiz0 InitialLevel
        let sendBuf1 = sendBuf0 `plusPtr` siz0
            bufsiz1 = bufsiz0 - siz0
        siz1 <- encCC sendBuf1 bufsiz1 HandshakeLevel
        return (siz0 + siz1)
      else
        encCC sendBuf0 bufsiz0 lvl
  where
    encCC sendBuf bufsiz lvl = do
        header <- mkHeader conn lvl
        mypn <- nextPacketNumber conn
        let plain = Plain (Flags 0) mypn [frame] 0
            ppkt = PlainPacket header plain
        siz <- fst <$> encodePlainPacket conn sendBuf bufsiz ppkt Nothing
        if siz >= 0 then do
            now <- getTimeMicrosecond
            qlogSent conn ppkt now
            return siz
          else
            return 0

closer :: Microseconds -> IO Int -> IO Int -> IO () -> IO ()
closer (Microseconds pto) send recv hook = loop (3 :: Int)
  where
    loop 0 = return ()
    loop n = do
        _ <- send
        getTimeMicrosecond >>= skip (Microseconds pto)
        mx <- timeout (Microseconds (pto .>>. 1)) $ recv
        case mx of
          Nothing -> hook
          Just 0  -> return ()
          Just _  -> loop (n - 1)
    skip tmo@(Microseconds duration) base = do
        mx <- timeout tmo recv
        case mx of
          Nothing -> return ()
          Just 0  -> return ()
          Just _  -> do
              Microseconds elapsed <- getElapsedTimeMicrosecond base
              let duration' = duration - elapsed
              when (duration' >= 5000) $ skip (Microseconds duration') base
