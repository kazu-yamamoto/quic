{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client.Run (
    run
  ) where

import qualified Network.Socket as NS
import UnliftIO.Async
import UnliftIO.Concurrent
import qualified UnliftIO.Exception as E

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
import Network.QUIC.Socket
import Network.QUIC.Types

----------------------------------------------------------------

-- | Running a QUIC client.
--   A UDP socket is created according to 'ccServerName' and 'ccPortName'.
--
--   If 'ccAutoMigration' is 'True', a unconnected socket is made.
--   Otherwise, a connected socket is made.
--   Use the 'migrate' API for the connected socket.
run :: ClientConfig -> (Connection -> IO a) -> IO a
-- Don't use handleLogUnit here because of a return value.
run conf client = case ccVersions conf of
  []     -> E.throwIO NoVersionIsSpecified
  ver1:_ -> do
      ex <- E.try $ runClient conf client ver1
      case ex of
        Right v                        -> return v
        Left (NextVersion Nothing)     -> E.throwIO VersionNegotiationFailed
        Left (NextVersion (Just ver2)) -> runClient conf client ver2

runClient :: ClientConfig -> (Connection -> IO a) -> Version -> IO a
runClient conf client0 ver = do
    E.bracket open clse $ \(ConnRes conn send recv myAuthCIDs reader) -> do
        forkIO reader    >>= addReader conn
        forkIO timeouter >>= addTimeouter conn
        handshaker <- handshakeClient conf conn myAuthCIDs
        let client = do
                if ccUse0RTT conf then
                    wait0RTTReady conn
                  else
                    wait1RTTReady conn
                setToken conn $ resumptionToken $ ccResumption conf
                client0 conn
            ldcc = connLDCC conn
            supporters = foldr1 concurrently_ [handshaker
                                              ,sender   conn send
                                              ,receiver conn recv
                                              ,resender  ldcc
                                              ,ldccTimer ldcc
                                              ]
            runThreads = do
                er <- race supporters client
                case er of
                  Left () -> E.throwIO MustNotReached
                  Right r -> return r
        E.trySyncOrAsync runThreads >>= closure conn ldcc
  where
    open = createClientConnection conf ver
    clse connRes = do
        let conn = connResConnection connRes
        setDead conn
        freeResources conn
        killReaders conn
        socks <- getSockets conn
        mapM_ NS.close socks
        join $ replaceKillTimeouter conn

createClientConnection :: ClientConfig -> Version -> IO ConnRes
createClientConnection conf@ClientConfig{..} ver = do
    (s0,sa0) <- if ccAutoMigration then
                  udpClientSocket ccServerName ccPortName
                else
                  udpClientConnectedSocket ccServerName ccPortName
    q <- newRecvQ
    sref <- newIORef [s0]
    let send buf siz = do
            s:_ <- readIORef sref
            if ccAutoMigration then
                void $ NS.sendBufTo s buf siz sa0
              else
                void $ NS.sendBuf s buf siz
        recv = recvClient q
    myCID   <- newCID
    peerCID <- newCID
    now <- getTimeMicrosecond
    (qLog, qclean) <- dirQLogger ccQLog now peerCID "client"
    let debugLog msg | ccDebugLog = stdoutLogger msg
                     | otherwise  = return ()
    debugLog $ "Original CID: " <> bhow peerCID
    let myAuthCIDs   = defaultAuthCIDs { initSrcCID = Just myCID }
        peerAuthCIDs = defaultAuthCIDs { initSrcCID = Just peerCID, origDstCID = Just peerCID }
    conn <- clientConnection conf ver myAuthCIDs peerAuthCIDs debugLog qLog ccHooks sref q
    addResource conn qclean
    initializeCoder conn InitialLevel $ initialSecrets ver peerCID
    setupCryptoStreams conn -- fixme: cleanup
    let pktSiz0 = fromMaybe 0 ccPacketSize
        pktSiz = (defaultPacketSize sa0 `max` pktSiz0) `min` maximumPacketSize sa0
    setMaxPacketSize conn pktSiz
    setInitialCongestionWindow (connLDCC conn) pktSiz
    setAddressValidated conn
    when ccAutoMigration $ setServerAddr conn sa0
    let reader = readerClient ccVersions s0 conn -- dies when s0 is closed.
    return $ ConnRes conn send recv myAuthCIDs reader
