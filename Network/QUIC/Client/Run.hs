{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE InterruptibleFFI #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client.Run (
    run,
    migrate,
) where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import Foreign.C.Types
import qualified Network.Socket as NS

import Network.QUIC.Client.Reader
import Network.QUIC.Closer
import Network.QUIC.Common
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Crypto
import Network.QUIC.Handshake
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Parameters
import Network.QUIC.QLogger
import Network.QUIC.Receiver
import Network.QUIC.Recovery
import Network.QUIC.Sender
import Network.QUIC.Types

----------------------------------------------------------------

-- | Running a QUIC client.
--   A UDP socket is created according to 'ccServerName' and 'ccPortName'.
run :: ClientConfig -> (Connection -> IO a) -> IO a
-- Don't use handleLogUnit here because of a return value.
run conf client = do
    let resInfo = ccResumption conf
        verInfo = case resumptionSession resInfo of
            []
                | resumptionToken resInfo == emptyToken ->
                    let ver = ccVersion conf
                        vers = ccVersions conf
                     in VersionInfo ver vers
            _ -> let ver = resumptionVersion resInfo in VersionInfo ver [ver]
    -- Exceptions except NextVersion are passed through.
    ex <- E.try $ runClient conf client False verInfo
    case ex of
        Right v -> return v
        -- Other exceptions go though.
        Left (NextVersion nextVerInfo)
            | verInfo == brokenVersionInfo -> E.throwIO VersionNegotiationFailed
            | otherwise -> runClient conf client True nextVerInfo

runClient :: ClientConfig -> (Connection -> IO a) -> Bool -> VersionInfo -> IO a
runClient conf client0 isICVN verInfo = do
    E.bracket open clse $ \(ConnRes conn myAuthCIDs reader) -> do
        forkManaged conn reader
        let conf' =
                conf
                    { ccParameters =
                        (ccParameters conf)
                            { versionInformation = Just verInfo
                            }
                    }
        setIncompatibleVN conn isICVN -- must be before handshaker
        setToken conn $ resumptionToken $ ccResumption conf
        handshaker <- handshakeClient conf' conn myAuthCIDs
        let client = do
                -- For 0-RTT, the following variables should be initialized
                -- in advance.
                setTxMaxStreams conn $ initialMaxStreamsBidi defaultParameters
                setTxUniMaxStreams conn $ initialMaxStreamsUni defaultParameters
                if ccUse0RTT conf
                    then wait0RTTReady conn
                    else wait1RTTReady conn
                client0 conn
            ldcc = connLDCC conn
            supporters =
                foldr1
                    concurrently_
                    [ handshaker
                    , sender conn
                    , receiver conn
                    , resender ldcc
                    , ldccTimer ldcc
                    ]
            runThreads = do
                er <- race supporters client
                case er of
                    Left () -> E.throwIO MustNotReached
                    Right r -> return r
        when (ccWatchDog conf) $ forkManaged conn $ watchDog conn
        ex <- E.try runThreads
        sendFinal conn
        closure conn ldcc ex
  where
    open = createClientConnection conf verInfo
    clse connRes = do
        let conn = connResConnection connRes
        setDead conn
        freeResources conn
        killReaders conn

createClientConnection :: ClientConfig -> VersionInfo -> IO ConnRes
createClientConnection conf@ClientConfig{..} verInfo = do
    (sock, peersa) <- clientSocket ccServerName ccPortName
    when ccSockConnected $ NS.connect sock peersa
    q <- newRecvQ
    sref <- newIORef sock
    pathInfo <- newPathInfo peersa
    piref <- newIORef $ PeerInfo pathInfo Nothing
    let send buf siz
            | ccSockConnected = do
                s <- readIORef sref
                void $ NS.sendBuf s buf siz
            | otherwise = do
                s <- readIORef sref
                PeerInfo pinfo _ <- readIORef piref
                void $ NS.sendBufTo s buf siz $ peerSockAddr pinfo
        recv = recvClient q
    myCID <- newCID
    -- Creating peer's CIDDB with the temporary CID.  This is
    -- overridden by resetPeerCID later since no sequence number is
    -- assigned to the temporary CID by spec.
    peerCID <- newCID
    now <- getTimeMicrosecond
    (qLog, qclean) <- dirQLogger ccQLog now peerCID "client"
    let debugLog msg
            | ccDebugLog = stdoutLogger msg
            | otherwise = return ()
    debugLog $ "Original CID: " <> bhow peerCID
    let myAuthCIDs = defaultAuthCIDs{initSrcCID = Just myCID}
        peerAuthCIDs = defaultAuthCIDs{initSrcCID = Just peerCID, origDstCID = Just peerCID}
    genSRT <- makeGenStatelessReset
    conn <-
        clientConnection
            conf
            verInfo
            myAuthCIDs
            peerAuthCIDs
            debugLog
            qLog
            ccHooks
            sref
            piref
            q
            send
            recv
            genSRT
    setSockConnected conn ccSockConnected
    addResource conn qclean
    modifytPeerParameters conn ccResumption
    let ver = chosenVersion verInfo
    initializeCoder conn InitialLevel $ initialSecrets ver peerCID
    setupCryptoStreams conn -- fixme: cleanup
    let pktSiz0 = fromMaybe 0 ccPacketSize
        pktSiz = (defaultPacketSize peersa `max` pktSiz0) `min` maximumPacketSize peersa
    setMaxPacketSize conn pktSiz
    setInitialCongestionWindow (connLDCC conn) pktSiz
    setAddressValidated pathInfo
    let reader = readerClient sock conn -- dies when s0 is closed.
    return $ ConnRes conn myAuthCIDs reader

-- | Creating a new socket and execute a path validation
--   with a new connection ID. Typically, this is used
--   for migration in the case where 'ccSockConnected' is 'True'.
--   But this can also be used even when the value is 'False'.
migrate :: Connection -> IO Bool
migrate conn = controlConnection conn ActiveMigration

watchDog :: Connection -> IO ()
watchDog conn = E.bracket c_open_socket c_close_socket loop
  where
    loop s = do
        ret <- c_watch_socket s
        case ret of
            -1 -> loop s
            -2 -> return ()
            _ -> do
                _ <- migrate conn
                -- prevent calling "migrate" frequently
                threadDelay 100000
                loop s

foreign import ccall unsafe "open_socket"
    c_open_socket :: IO CInt

foreign import ccall interruptible "watch_socket"
    c_watch_socket :: CInt -> IO CInt

foreign import ccall unsafe "close_socket"
    c_close_socket :: CInt -> IO CInt
