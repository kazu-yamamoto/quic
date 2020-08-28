{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Misc (
    setVersion
  , getVersion
  , getSockInfo
  , setSockInfo
  , killHandshaker
  , setKillHandshaker
  , clearKillHandshaker
  , getPeerAuthCIDs
  , setPeerAuthCIDs
  , getMyParameters
  , getPeerParameters
  , setPeerParameters
  , delayedAck
  , resetDealyedAck
  , setMaxPacketSize
  , exitConnection
  , addResource
  , freeResources
  , addThreadIdResource
  , readMinIdleTimeout
  , setMinIdleTimeout
  ) where

import Control.Concurrent
import qualified Control.Exception as E
import Network.Socket
import System.Mem.Weak

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Timeout
import Network.QUIC.Types

----------------------------------------------------------------

setVersion :: Connection -> Version -> IO ()
setVersion Connection{..} ver = writeIORef quicVersion ver

getVersion :: Connection -> IO Version
getVersion Connection{..} = readIORef quicVersion

----------------------------------------------------------------

getSockInfo :: Connection -> IO (Socket, RecvQ)
getSockInfo Connection{..} = readIORef sockInfo

setSockInfo :: Connection -> (Socket, RecvQ) -> IO ()
setSockInfo Connection{..} si = writeIORef sockInfo si

----------------------------------------------------------------

killHandshaker :: Connection -> IO ()
killHandshaker Connection{..} = do
    join $ readIORef killHandshakerAct
    writeIORef killHandshakerAct $ return ()

clearKillHandshaker :: Connection -> IO ()
clearKillHandshaker Connection{..} =
    writeIORef killHandshakerAct $ return ()

setKillHandshaker :: Connection -> ThreadId -> IO ()
setKillHandshaker Connection{..} tid = do
    wtid <- mkWeakThreadId tid
    writeIORef killHandshakerAct $ do
        mtid <- deRefWeak wtid
        case mtid of
          Nothing  -> return ()
          Just tid' -> killThread tid'

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
        new <- cfire (Microseconds 20000) $ sendAck
        join $ atomicModifyIORef' delayedAckCancel $ \old -> (new, old)
    when send $ do
        let new = return ()
        join $ atomicModifyIORef' delayedAckCancel $ \old -> (new, old)
        sendAck
  where
    sendAck = putOutput conn $ OutControl RTT1Level []
    check 1 = (0,   (1,  True))
    check n = (n+1, (n, False))

resetDealyedAck :: Connection -> IO ()
resetDealyedAck Connection{..} = do
    writeIORef delayedAckCount 0
    let new = return ()
    join $ atomicModifyIORef' delayedAckCancel $ \old -> (new, old)

----------------------------------------------------------------

setMaxPacketSize :: Connection -> Int -> IO ()
setMaxPacketSize Connection{..} n = writeIORef (maxPacketSize connState) n

----------------------------------------------------------------

exitConnection :: Connection -> QUICError -> IO ()
exitConnection Connection{..} ue = E.throwTo connThreadId ue

----------------------------------------------------------------

addResource :: Connection -> IO () -> IO ()
addResource Connection{..} f = atomicModifyIORef'' connResources $ \fs -> f >> fs

freeResources :: Connection -> IO ()
freeResources Connection{..} = do
    doFree <- atomicModifyIORef' connResources $ \fs -> (return (), fs)
    doFree

addThreadIdResource :: Connection -> ThreadId -> IO ()
addThreadIdResource conn tid = do
    wtid <- mkWeakThreadId tid
    let clear = clearThread wtid
    addResource conn clear

clearThread :: Weak ThreadId -> IO ()
clearThread wtid = do
    mtid <- deRefWeak wtid
    case mtid of
      Nothing  -> return ()
      Just tid -> killThread tid

----------------------------------------------------------------

readMinIdleTimeout :: Connection -> IO Microseconds
readMinIdleTimeout Connection{..} = readIORef minIdleTimeout

setMinIdleTimeout :: Connection -> Microseconds -> IO ()
setMinIdleTimeout Connection{..} us
  | us == Microseconds 0 = return ()
  | otherwise            = atomicModifyIORef'' minIdleTimeout modify
  where
    modify us0 = min us us0
