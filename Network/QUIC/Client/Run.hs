{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client.Run (
    runQUICClient
  , clientCertificateChain
  ) where

import qualified Control.Exception as OldE
import Data.X509 (CertificateChain)
import qualified Network.Socket as NS
import UnliftIO.Async
import UnliftIO.Concurrent
import qualified UnliftIO.Exception as E

import Network.QUIC.Client.Reader
import Network.QUIC.Closer
import Network.QUIC.Common
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
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
runQUICClient :: ClientConfig -> (Connection -> IO a) -> IO a
-- Don't use handleLogUnit here because of a return value.
runQUICClient conf client = case ccVersions conf of
  []     -> E.throwIO NoVersionIsSpecified
  ver1:_ -> do
      ex <- OldE.try $ runClient conf client ver1
      case ex of
        Right v                     -> return v
        Left se@(OldE.SomeException e)
          | Just (NextVersion ver2) <- OldE.fromException se
                                    -> runClient conf client ver2
          | otherwise               -> E.throwIO e

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
            runThreads = race supporters client
        OldE.try runThreads >>= closure conn ldcc
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
    (s0,sa0) <- udpClientConnectedSocket ccServerName ccPortName
    q <- newRecvQ
    sref <- newIORef [s0]
    let send buf siz = do
            s:_ <- readIORef sref
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
    let reader = readerClient ccVersions s0 conn -- dies when s0 is closed.
    return $ ConnRes conn send recv myAuthCIDs reader

----------------------------------------------------------------

-- | Getting a certificate chain.
clientCertificateChain :: Connection -> IO (Maybe CertificateChain)
clientCertificateChain conn
  | isClient conn = return Nothing
  | otherwise     = getCertificateChain conn
