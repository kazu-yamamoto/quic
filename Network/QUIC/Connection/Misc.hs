{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Misc (
    setVersion
  , getVersion
  , setMyCID
  , getMyCID
  , setPeerCID
  , getPeerCID
  , setThreadIds
  , clearThreads
  ) where

import Control.Concurrent
import Data.IORef
import System.Mem.Weak

import Network.QUIC.Connection.Types
import Network.QUIC.Types

----------------------------------------------------------------

setVersion :: Connection -> Version -> IO ()
setVersion Connection{..} ver = writeIORef connVersion ver

getVersion :: Connection -> IO Version
getVersion Connection{..} = readIORef connVersion

----------------------------------------------------------------

setMyCID :: Connection -> CID -> IO ()
setMyCID Connection{..} mcid = writeIORef myCID mcid

getMyCID :: Connection -> IO CID
getMyCID Connection{..} = readIORef myCID

----------------------------------------------------------------

setPeerCID :: Connection -> CID -> IO ()
setPeerCID Connection{..} pcid = writeIORef peerCID pcid

getPeerCID :: Connection -> IO CID
getPeerCID Connection{..} = readIORef peerCID

----------------------------------------------------------------

setThreadIds :: Connection -> [ThreadId] -> IO ()
setThreadIds Connection{..} tids = do
    wtids <- mapM mkWeakThreadId tids
    writeIORef threadIds wtids

clearThreads :: Connection -> IO ()
clearThreads Connection{..} = do
    wtids <- readIORef threadIds
    mapM_ kill wtids
    writeIORef threadIds []
  where
    kill wtid = do
        mtid <- deRefWeak wtid
        case mtid of
          Nothing  -> return ()
          Just tid -> killThread tid
