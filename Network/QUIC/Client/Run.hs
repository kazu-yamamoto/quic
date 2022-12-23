{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Client.Run (
    run
  , migrate
  ) where

import qualified Network.Socket as NS
import Network.UDP (UDPSocket(..))
import qualified Network.UDP as UDP
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
run conf client = NS.withSocketsDo $ do
  let resInfo = ccResumption conf
      verInfo = case resumptionSession resInfo of
        Nothing | resumptionToken resInfo == emptyToken ->
                  let vers = ccVersions conf
                      ver = head vers
                  in VersionInfo ver vers
        _  -> let ver = resumptionVersion resInfo in VersionInfo ver [ver]
  ex <- E.try $ runClient conf client False verInfo
  case ex of
    Right v                     -> return v
    Left (NextVersion nextVerInfo)
      | verInfo == brokenVersionInfo -> E.throwIO VersionNegotiationFailed
      | otherwise                    -> runClient conf client True nextVerInfo

runClient :: ClientConfig -> (Connection -> IO a) -> Bool -> VersionInfo -> IO a
runClient conf client0 isICVN verInfo = do
    E.bracket open clse $ \(ConnRes conn myAuthCIDs reader) -> do
        forkIO reader    >>= addReader conn
        forkIO timeouter >>= addTimeouter conn
        let conf' = conf {
                ccParameters = (ccParameters conf) {
                      versionInformation = Just verInfo
                    }
              }
        setIncompatibleVN conn isICVN -- must be before handshaker
        handshaker <- handshakeClient conf' conn myAuthCIDs
        let client = do
                if ccUse0RTT conf then
                    wait0RTTReady conn
                  else
                    wait1RTTReady conn
                setToken conn $ resumptionToken $ ccResumption conf
                client0 conn
            ldcc = connLDCC conn
            supporters = foldr1 concurrently_ [handshaker
                                              ,sender   conn
                                              ,receiver conn
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
    open = createClientConnection conf verInfo
    clse connRes = do
        let conn = connResConnection connRes
        setDead conn
        freeResources conn
        killReaders conn
        getSocket conn >>= UDP.close
        join $ replaceKillTimeouter conn

createClientConnection :: ClientConfig -> VersionInfo -> IO ConnRes
createClientConnection conf@ClientConfig{..} verInfo = do
    us@(UDPSocket _ sa _) <- UDP.clientSocket ccServerName ccPortName (not ccAutoMigration)
    q <- newRecvQ
    sref <- newIORef us
    let send = \buf siz -> do
            cs <- readIORef sref
            UDP.sendBuf cs buf siz
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
    conn <- clientConnection conf verInfo myAuthCIDs peerAuthCIDs debugLog qLog ccHooks sref q send recv
    addResource conn qclean
    let ver = chosenVersion verInfo
    initializeCoder conn InitialLevel $ initialSecrets ver peerCID
    setupCryptoStreams conn -- fixme: cleanup
    let pktSiz0 = fromMaybe 0 ccPacketSize
        pktSiz = (defaultPacketSize sa `max` pktSiz0) `min` maximumPacketSize sa
    setMaxPacketSize conn pktSiz
    setInitialCongestionWindow (connLDCC conn) pktSiz
    setAddressValidated conn
    let reader = readerClient us conn -- dies when s0 is closed.
    return $ ConnRes conn myAuthCIDs reader

-- | Creating a new socket and execute a path validation
--   with a new connection ID. Typically, this is used
--   for migration in the case where 'ccAutoMigration' is 'False'.
--   But this can also be used even when the value is 'True'.
migrate :: Connection -> IO Bool
migrate conn = controlConnection conn ActiveMigration
