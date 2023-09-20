{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Network.QUIC.Connection.Misc (
    setVersionInfo
  , getVersionInfo
  , setVersion
  , getVersion
  , getOriginalVersion
  , getSocket
  , setSocket
  , clearSocket
  , getPeerAuthCIDs
  , setPeerAuthCIDs
  , getClientDstCID
  , getMyParameters
  , getPeerParameters
  , setPeerParameters
  , delayedAck
  , resetDealyedAck
  , setMaxPacketSize
  , addReader
  , killReaders
  , addResource
  , freeResources
  , readMinIdleTimeout
  , setMinIdleTimeout
  , sendFrames
  , closeConnection
  , abortConnection
  ) where

import Network.UDP
import System.Mem.Weak
import UnliftIO.Concurrent
import qualified UnliftIO.Exception as E

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Timeout
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Types

----------------------------------------------------------------

setVersionInfo :: Connection -> VersionInfo -> IO ()
setVersionInfo Connection{..} ver = writeIORef quicVersionInfo ver

getVersionInfo :: Connection -> IO VersionInfo
getVersionInfo Connection{..} = readIORef quicVersionInfo

setVersion :: Connection -> Version -> IO ()
setVersion Connection{..} ver = atomicModifyIORef'' quicVersionInfo $ \vi ->
  vi { chosenVersion = ver }

getVersion :: Connection -> IO Version
getVersion conn = chosenVersion <$> getVersionInfo conn

getOriginalVersion :: Connection -> Version
getOriginalVersion = chosenVersion . origVersionInfo

----------------------------------------------------------------

getSocket :: Connection -> IO UDPSocket
getSocket Connection{..} = readIORef udpSocket

setSocket :: Connection -> UDPSocket -> IO UDPSocket
setSocket Connection{..} sock = atomicModifyIORef' udpSocket $
    \sock0 -> (sock, sock0)

clearSocket :: Connection -> IO UDPSocket
clearSocket Connection{..} = atomicModifyIORef' udpSocket (undefined,)

----------------------------------------------------------------

getMyAuthCIDs :: Connection -> IO AuthCIDs
getMyAuthCIDs Connection{..} = readIORef connMyAuthCIDs

getPeerAuthCIDs :: Connection -> IO AuthCIDs
getPeerAuthCIDs Connection{..} = readIORef connPeerAuthCIDs

setPeerAuthCIDs :: Connection -> (AuthCIDs -> AuthCIDs) -> IO ()
setPeerAuthCIDs Connection{..} f = atomicModifyIORef'' connPeerAuthCIDs f

getClientDstCID :: Connection -> IO CID
getClientDstCID conn = do
    cids <- if isClient conn then
              getPeerAuthCIDs conn
            else
              getMyAuthCIDs conn
    return $ case retrySrcCID cids of
      Nothing   -> fromJust $ origDstCID cids
      Just dcid -> dcid

----------------------------------------------------------------

getMyParameters :: Connection -> Parameters
getMyParameters Connection{..} = myParameters

----------------------------------------------------------------

getPeerParameters :: Connection -> IO Parameters
getPeerParameters Connection{..} = readIORef peerParameters

setPeerParameters :: Connection -> Parameters -> IO ()
setPeerParameters Connection{..} params = writeIORef peerParameters params

----------------------------------------------------------------

delayedAck :: Connection -> IO ()
delayedAck conn@Connection{..} = do
    (oldcnt,send_) <- atomicModifyIORef' delayedAckCount check
    when (oldcnt == 0) $ do
        new <- cfire conn (Microseconds 20000) sendAck
        join $ atomicModifyIORef' delayedAckCancel (new,)
    when send_ $ do
        let new = return ()
        join $ atomicModifyIORef' delayedAckCancel (new,)
        sendAck
  where
    sendAck = putOutput conn $ OutControl RTT1Level [] $ return ()
    check 1 = (0,   (1,  True))
    check n = (n+1, (n, False))

resetDealyedAck :: Connection -> IO ()
resetDealyedAck Connection{..} = do
    writeIORef delayedAckCount 0
    let new = return ()
    join $ atomicModifyIORef' delayedAckCancel (new,)

----------------------------------------------------------------

setMaxPacketSize :: Connection -> Int -> IO ()
setMaxPacketSize Connection{..} n = writeIORef (maxPacketSize connState) n

----------------------------------------------------------------

addResource :: Connection -> IO () -> IO ()
addResource Connection{..} f = atomicModifyIORef'' connResources $ \fs -> f' >> fs
  where
    f' = f `E.catch` (\(E.SomeException _) -> return ())

freeResources :: Connection -> IO ()
freeResources Connection{..} =
    join $ atomicModifyIORef' connResources (return (),)

----------------------------------------------------------------

addReader :: Connection -> ThreadId -> IO ()
addReader Connection{..} tid = do
    wtid <- mkWeakThreadId tid
    atomicModifyIORef'' readers $ \m -> do
        m
        deRefWeak wtid >>= mapM_ killThread

killReaders :: Connection -> IO ()
killReaders Connection{..} = join $ readIORef readers

----------------------------------------------------------------

readMinIdleTimeout :: Connection -> IO Microseconds
readMinIdleTimeout Connection{..} = readIORef minIdleTimeout

setMinIdleTimeout :: Connection -> Microseconds -> IO ()
setMinIdleTimeout Connection{..} us
  | us == Microseconds 0 = return ()
  | otherwise            = atomicModifyIORef'' minIdleTimeout modify
  where
    modify us0 = min us us0

----------------------------------------------------------------

sendFrames :: Connection -> EncryptionLevel -> [Frame] -> IO ()
sendFrames conn lvl frames = putOutput conn $ OutControl lvl frames $ return ()

-- | Closing a connection with/without a transport error.
--   Internal threads should use this.
closeConnection :: TransportError -> ReasonPhrase -> IO ()
closeConnection err desc = E.throwIO quicexc
  where
    quicexc = TransportErrorIsSent err desc

-- | Closing a connection with an application protocol error.
abortConnection :: Connection -> ApplicationProtocolError -> ReasonPhrase -> IO ()
abortConnection conn err desc = E.throwTo (mainThreadId conn) $ Abort err desc
