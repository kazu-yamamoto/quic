{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Misc where

import Control.Concurrent
import Data.IORef
import System.Mem.Weak

import Network.QUIC.Connection.Types
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

setPeerCID :: Connection -> CID -> IO ()
setPeerCID Connection{..} pcid = writeIORef peerCID pcid

getPeerCID :: Connection -> IO CID
getPeerCID Connection{..} = readIORef peerCID

----------------------------------------------------------------

setThreadIds :: Connection -> [ThreadId] -> IO ()
setThreadIds conn tids = do
    wtids <- mapM mkWeakThreadId tids
    writeIORef (threadIds conn) wtids

clearThreads :: Connection -> IO ()
clearThreads conn = do
    wtids <- readIORef (threadIds conn)
    mapM_ kill wtids
    writeIORef (threadIds conn) []
  where
    kill wtid = do
        mtid <- deRefWeak wtid
        case mtid of
          Nothing  -> return ()
          Just tid -> killThread tid

----------------------------------------------------------------

setToken :: Connection -> Token -> IO ()
setToken conn token = writeIORef (connToken conn) token

getToken :: Connection -> IO Token
getToken conn = readIORef $ connToken conn

----------------------------------------------------------------

getResumptionInfo :: Connection -> IO ResumptionInfo
getResumptionInfo conn = readIORef $ resumptionInfo conn

----------------------------------------------------------------

setNewToken :: Connection -> Token -> IO ()
setNewToken conn token = modifyIORef (resumptionInfo conn) $ \res -> res { resumptionToken = token }
