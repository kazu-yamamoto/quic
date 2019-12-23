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

----------------------------------------------------------------

setToken :: Connection -> Token -> IO ()
setToken Connection{..} token = modifyIORef' roleInfo $ \ci -> ci { clientInitialToken = token }

getToken :: Connection -> IO Token
getToken Connection{..} = clientInitialToken <$> readIORef roleInfo

----------------------------------------------------------------

getResumptionInfo :: Connection -> IO ResumptionInfo
getResumptionInfo Connection{..} = resumptionInfo <$> readIORef roleInfo

----------------------------------------------------------------

setResumptionSession :: Connection -> SessionEstablish
setResumptionSession Connection{..} si sd = modifyIORef' roleInfo $ \ci -> ci {
    resumptionInfo = (resumptionInfo ci) { resumptionSession = Just (si,sd) }
  }

setNewToken :: Connection -> Token -> IO ()
setNewToken Connection{..} token = modifyIORef' roleInfo $ \ci -> ci {
    resumptionInfo = (resumptionInfo ci) { resumptionToken = token }
  }

----------------------------------------------------------------

setServerRoleInfo :: Connection -> (CID -> IO ()) -> (CID -> IO ()) -> IO ()
setServerRoleInfo Connection{..} regisrer unregister = writeIORef roleInfo si
  where
    si = ServerInfo {
        routeRegister = regisrer
      , routeUnregister = unregister
      }
