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
setToken conn token =
    modifyIORef' (roleInfo conn) $ \ci -> ci { connToken = token }

getToken :: Connection -> IO Token
getToken conn = connToken <$> readIORef (roleInfo conn)

----------------------------------------------------------------

getResumptionInfo :: Connection -> IO ResumptionInfo
getResumptionInfo conn = resumptionInfo <$> readIORef (roleInfo conn)

----------------------------------------------------------------

setResumptionSession :: Connection -> SessionEstablish
setResumptionSession conn si sd = modifyIORef' (roleInfo conn) $ \ci -> ci {
    resumptionInfo = (resumptionInfo ci) { resumptionSession = Just (si,sd) }
  }

setNewToken :: Connection -> Token -> IO ()
setNewToken conn token = modifyIORef' (roleInfo conn) $ \ci -> ci {
    resumptionInfo = (resumptionInfo ci) { resumptionToken = token }
  }

----------------------------------------------------------------

setServerRoleInfo :: Connection -> (CID -> IO ()) -> (CID -> IO ()) -> IO ()
setServerRoleInfo conn regisrer unregister = writeIORef (roleInfo conn) si
  where
    si = ServerInfo {
        routeRegister = regisrer
      , routeUnregister = unregister
      }
