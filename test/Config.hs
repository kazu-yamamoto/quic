{-# LANGUAGE OverloadedStrings #-}

module Config (
    makeTestServerConfig,
    makeTestServerConfigR,
    testClientConfig,
    testClientConfigR,
    setServerQlog,
    setClientQlog,
    withPipe,
    withPipeStray,
    Scenario (..),
    newSessionManager,
) where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Bits ((.&.))
import Data.IORef
import qualified Data.List as L
import qualified Data.List.NonEmpty as NE
import Network.Socket
import Network.Socket.ByteString
import Network.TLS hiding (Version)

import Network.QUIC.Client
import Network.QUIC.Internal

makeTestServerConfig :: IO ServerConfig
makeTestServerConfig = do
    cred <-
        either error id
            <$> credentialLoadX509 "test/servercert.pem" "test/serverkey.pem"
    let credentials = Credentials [cred]
    return
        testServerConfig
            { scCredentials = credentials
            , scALPN = Just chooseALPN
            }

testServerConfig :: ServerConfig
testServerConfig =
    defaultServerConfig
        { -- Don't use "0.0.0.0" and "::" for Windows (UDP dispatching bug)
          scAddresses = [("127.0.0.1", 50003)]
        , scParameters =
            (scParameters defaultServerConfig)
                { maxIdleTimeout = Milliseconds 10000
                }
        }

makeTestServerConfigR :: IO ServerConfig
makeTestServerConfigR = do
    cred <-
        either error id
            <$> credentialLoadX509 "test/servercert.pem" "test/serverkey.pem"
    let credentials = Credentials [cred]
    return $
        setServerQlog
            testServerConfigR
                { scCredentials = credentials
                , scALPN = Just chooseALPN
                }

testServerConfigR :: ServerConfig
testServerConfigR =
    defaultServerConfig
        { -- Don't use "0.0.0.0" and "::" for Windows (UDP dispatching bug)
          scAddresses = [("127.0.0.1", 50003)]
        , scParameters =
            (scParameters defaultServerConfig)
                { maxIdleTimeout = Milliseconds 10000
                }
        }

testClientConfig :: ClientConfig
testClientConfig =
    defaultClientConfig
        { ccServerName = "127.0.0.1"
        , ccPortName = "50003"
        , ccValidate = False
        , ccDebugLog = True
        , ccParameters =
            (ccParameters defaultClientConfig)
                { maxIdleTimeout = Milliseconds 10000
                }
        }

testClientConfigR :: ClientConfig
testClientConfigR =
    defaultClientConfig
        { ccServerName = "127.0.0.1"
        , ccPortName = "50002"
        , ccValidate = False
        , ccDebugLog = True
        , ccParameters =
            (ccParameters defaultClientConfig)
                { maxIdleTimeout = Milliseconds 10000
                }
        }

-- | Write qlog for the connections that go through 'withPipe'.
--
-- These are the tests that lose packets on purpose, and so the ones that
-- stall.  A stall costs the idle timeout and reports a test name and
-- \"ConnectionIsTimeout\", which says nothing about why; the qlog says which
-- packets went where, what the congestion window was doing and when a timer
-- fired.  Two stalls found at a rate of one run in a few hundred were read
-- straight off these traces, and neither would have been diagnosable
-- without them.  CI keeps the directory when a job fails.
setServerQlog :: ServerConfig -> ServerConfig
setServerQlog sc = sc{scQLog = Just "qlog"}

setClientQlog :: ClientConfig -> ClientConfig
setClientQlog cc = cc{ccQLog = Just "qlog"}

data Scenario
    = Randomly Int
    | DropClientPacket [Int]
    | DropServerPacket [Int]

withPipe :: Scenario -> IO () -> IO ()
withPipe = withPipeWith False

-- | 'withPipe', with one short-header datagram delivered to the relay's
-- socket before the relay starts reading.
--
-- That is what the CONNECTION_CLOSE of the connection that just closed looks
-- like when it lands after this socket has taken over the port, and taking it
-- for the client ties the relay to a peer with nothing left to say.  The test
-- that uses this fails within the idle timeout if the relay ever goes back to
-- latching onto the first datagram it sees.
withPipeStray :: Scenario -> IO () -> IO ()
withPipeStray = withPipeWith True

withPipeWith :: Bool -> Scenario -> IO () -> IO ()
withPipeWith stray scenario body = do
    addrC <- resolve "50002"
    let saC = addrAddress addrC
    addrS <- resolve "50003"
    let saS = addrAddress addrS
    irefC <- newIORef 0
    irefS <- newIORef 0
    E.bracket (openSocket addrC) close $ \sockC ->
        E.bracket (openSocket addrS) close $ \sockS -> do
            setSocketOption sockC ReuseAddr 1
            setSocketOption sockS ReuseAddr 1
            bind sockC saC
            connect sockS saS
            when stray $
                E.bracket (openSocket addrC) close $ \sock ->
                    void $ sendTo sock (BS.pack [0x40, 1, 2, 3]) saC

            -- The relaying threads have to stop before the sockets close.
            -- Run at the end of body instead, the kills are skipped whenever
            -- body throws, and the threads are then left in recv on a socket
            -- the bracket has just closed.  That surfaces as "threadWait:
            -- invalid argument (Bad file descriptor)" from a thread nobody is
            -- watching, and buries whatever the test was really failing on.
            E.bracket (startRelay sockC sockS irefC irefS) stopRelay $ \_ -> body
  where
    startRelay sockC sockS irefC irefS = do
        -- from client
        tid0 <- forkIO $ do
            -- Wait for the client to introduce itself, and take the first
            -- long-header packet rather than the first datagram.
            --
            -- These sockets use one fixed port, so the socket for this test
            -- binds it a fraction of a millisecond after the previous test
            -- closed its own.  The client of that test signs off with a
            -- CONNECTION_CLOSE, and when that lands after the handover it is
            -- this socket that receives it.  Connecting to its sender ties
            -- the relay to a peer with nothing left to say, and the kernel
            -- then drops every datagram from the client we are here to
            -- relay: it sends Initial packets until the idle timeout and
            -- hears nothing, the server never sees the connection at all.
            --
            -- A client always opens with a long header; a leftover from an
            -- established connection is a short one.  That tells them apart.
            (bs, saO) <- waitForClientHello sockC
            connect sockC saO
            n0 <- atomicModifyIORef' irefC $ \x -> (x + 1, x)
            dropPacket0 <- shouldDrop scenario True n0
            unless dropPacket0 $ void $ send sockS bs
            forever $ do
                bs1 <- recv sockC 2048
                n <- atomicModifyIORef' irefC $ \x -> (x + 1, x)
                dropPacket <- shouldDrop scenario True n
                let isCC = BS.length bs1 < 200
                when (isCC || not dropPacket) $ void $ send sockS bs1
        -- from server
        tid1 <- forkIO $ forever $ do
            bs <- recv sockS 2048
            n <- atomicModifyIORef' irefS $ \x -> (x + 1, x)
            dropPacket <- shouldDrop scenario False n
            let isCC = BS.length bs < 200
            when (isCC || not dropPacket) $ void $ send sockC bs
        return (tid0, tid1)
    stopRelay (tid0, tid1) = killThread tid0 >> killThread tid1
    waitForClientHello sockC = do
        (bs, saO) <- recvFrom sockC 2048
        if not (BS.null bs) && BS.head bs .&. 0x80 /= 0
            then return (bs, saO)
            else waitForClientHello sockC
    hints =
        defaultHints
            { addrSocketType = Network.Socket.Datagram
            , addrFlags = [AI_NUMERICHOST]
            , addrFamily = AF_INET
            }
    resolve port =
        NE.head <$> getAddrInfo (Just hints) (Just "127.0.0.1") (Just port)
    shouldDrop (Randomly n) _ _ = do
        w <- getRandomOneByte
        return ((w `mod` fromIntegral n) == 0)
    shouldDrop (DropClientPacket ns) fromC pn
        | fromC = return (pn `elem` ns)
        | otherwise = return False
    shouldDrop (DropServerPacket ns) fromC pn
        | fromC = return False
        | otherwise = return (pn `elem` ns)

chooseALPN :: Version -> [ByteString] -> IO ByteString
chooseALPN _ver protos = return $ case mh3idx of
    Nothing -> case mhqidx of
        Nothing -> ""
        Just _ -> "hq"
    Just h3idx -> case mhqidx of
        Nothing -> "h3"
        Just hqidx -> if h3idx < hqidx then "h3" else "hq"
  where
    mh3idx = "h3" `L.elemIndex` protos
    mhqidx = "hq" `L.elemIndex` protos

newSessionManager :: IO SessionManager
newSessionManager = sessionManager <$> newIORef Nothing

sessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
sessionManager ref =
    noSessionManager
        { sessionEstablish = establish
        , sessionResume = resume
        , sessionResumeOnlyOnce = resume
        , sessionInvalidate = \_ -> return ()
        , sessionUseTicket = False
        }
  where
    establish sid sdata = writeIORef ref (Just (sid, sdata)) >> return Nothing
    resume sid = do
        mx <- readIORef ref
        case mx of
            Nothing -> return Nothing
            Just (s, d)
                | s == sid -> return $ Just d
                | otherwise -> return Nothing
