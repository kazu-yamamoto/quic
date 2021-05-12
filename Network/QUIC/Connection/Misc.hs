{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Network.QUIC.Connection.Misc (
    setVersion
  , getVersion
  , getSockets
  , addSocket
  , getPeerAuthCIDs
  , setPeerAuthCIDs
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
  ) where

import Control.Concurrent
import qualified Control.Exception as E
import Network.Socket
import System.Mem.Weak

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Timeout
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Types

----------------------------------------------------------------

setVersion :: Connection -> Version -> IO ()
setVersion Connection{..} ver = writeIORef quicVersion ver

getVersion :: Connection -> IO Version
getVersion Connection{..} = readIORef quicVersion

----------------------------------------------------------------

getSockets :: Connection -> IO [Socket]
getSockets Connection{..} = readIORef sockets

addSocket :: Connection -> Socket -> IO Socket
addSocket Connection{..} s1 = atomicModifyIORef' sockets $
    \ss@(s0:_) -> (s1:ss,s0)

----------------------------------------------------------------

getPeerAuthCIDs :: Connection -> IO AuthCIDs
getPeerAuthCIDs Connection{..} = readIORef handshakeCIDs

setPeerAuthCIDs :: Connection -> (AuthCIDs -> AuthCIDs) -> IO ()
setPeerAuthCIDs Connection{..} f = atomicModifyIORef'' handshakeCIDs f

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
    (oldcnt,send) <- atomicModifyIORef' delayedAckCount check
    when (oldcnt == 0) $ do
        new <- cfire conn (Microseconds 20000) sendAck
        join $ atomicModifyIORef' delayedAckCancel (new,)
    when send $ do
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
