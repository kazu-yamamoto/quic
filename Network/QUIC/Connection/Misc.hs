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
  , checkDelayedAck
  , checkDelayedAck'
  , resetDelayedAck
  , getMaxPacketSize
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
import Data.IORef
import Network.Socket
import System.Mem.Weak

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Parameters
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
setPeerAuthCIDs Connection{..} f = modifyIORef' handshakeCIDs f

----------------------------------------------------------------

getMyParameters :: Connection -> Parameters
getMyParameters Connection{..} = myParameters

----------------------------------------------------------------

getPeerParameters :: Connection -> IO Parameters
getPeerParameters Connection{..} = readIORef peerParameters

setPeerParameters :: Connection -> Parameters -> IO ()
setPeerParameters Connection{..} params = writeIORef peerParameters params

----------------------------------------------------------------

checkDelayedAck :: Connection -> IO Bool
checkDelayedAck Connection{..} = atomicModifyIORef' delayedAck check
  where
    check 9 = (0, True)
    check n = (n+1, False)

checkDelayedAck' :: Connection -> IO Bool
checkDelayedAck' Connection{..} = atomicModifyIORef' delayedAck check
  where
    check 0 = (0, False)
    check _ = (0, True)

resetDelayedAck :: Connection -> IO ()
resetDelayedAck Connection{..} = writeIORef delayedAck 0

----------------------------------------------------------------

getMaxPacketSize :: Connection -> IO Int
getMaxPacketSize Connection{..} = readIORef maxPacketSize

setMaxPacketSize :: Connection -> Int -> IO ()
setMaxPacketSize Connection{..} n = writeIORef maxPacketSize n

----------------------------------------------------------------

exitConnection :: Connection -> QUICError -> IO ()
exitConnection Connection{..} ue = E.throwTo connThreadId ue

----------------------------------------------------------------

addResource :: Connection -> IO () -> IO ()
addResource Connection{..} f = atomicModifyIORef' connResources $ \fs -> (f >> fs, ())

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

readMinIdleTimeout :: Connection -> IO Milliseconds
readMinIdleTimeout Connection{..} = readIORef minIdleTimeout

setMinIdleTimeout :: Connection -> Milliseconds -> IO ()
setMinIdleTimeout Connection{..} ms
  | ms == Milliseconds 0 = return ()
  | otherwise            = modifyIORef' minIdleTimeout modify
  where
    modify ms0 = min ms ms0
