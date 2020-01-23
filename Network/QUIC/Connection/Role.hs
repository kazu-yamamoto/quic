{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Role (
    getClientController
  , setClientController
  , clearClientController
  , getServerController
  , setServerController
  , clearServerController
  , setToken
  , getToken
  , getResumptionInfo
  , setRetried
  , getRetried
  , setResumptionSession
  , setNewToken
  , setRegister
  , getUnregister
  ) where

import Data.IORef
import Network.TLS.QUIC

import Network.QUIC.Connection.Types
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

setClientController :: Connection -> ClientController -> IO ()
setClientController Connection{..} ctl = modifyIORef' roleInfo $ \ci ->
  ci {connClientCntrl = ctl }

getClientController :: Connection -> IO ClientController
getClientController Connection{..} = connClientCntrl <$> readIORef roleInfo

clearClientController :: Connection -> IO ()
clearClientController conn = setClientController conn nullClientController


----------------------------------------------------------------

setServerController :: Connection -> ServerController -> IO ()
setServerController Connection{..} ctl = modifyIORef' roleInfo $ \ci ->
  ci {connServerCntrl = ctl }

getServerController :: Connection -> IO ServerController
getServerController Connection{..} = connServerCntrl <$> readIORef roleInfo

clearServerController :: Connection -> IO ()
clearServerController conn = setServerController conn nullServerController

----------------------------------------------------------------

setToken :: Connection -> Token -> IO ()
setToken Connection{..} token = modifyIORef' roleInfo $ \ci -> ci { clientInitialToken = token }

getToken :: Connection -> IO Token
getToken conn@Connection{..}
  | isClient conn = clientInitialToken <$> readIORef roleInfo
  | otherwise     = return emptyToken

----------------------------------------------------------------

getResumptionInfo :: Connection -> IO ResumptionInfo
getResumptionInfo Connection{..} = resumptionInfo <$> readIORef roleInfo

----------------------------------------------------------------

setRetried :: Connection -> Bool -> IO ()
setRetried Connection{..} r = modifyIORef' roleInfo $ \ci -> ci {
    resumptionInfo = (resumptionInfo ci) { resumptionRetry = r}
  }

getRetried :: Connection -> IO Bool
getRetried conn@Connection{..}
  | isClient conn = resumptionRetry . resumptionInfo <$> readIORef roleInfo
  | otherwise     = return False

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

setRegister :: Connection -> (CID -> IO ()) -> (CID -> IO ()) -> IO ()
setRegister Connection{..} regisrer unregister = modifyIORef' roleInfo $ \si -> si {
    routeRegister = regisrer
  , routeUnregister = unregister
  }

getUnregister :: Connection -> IO (CID -> IO ())
getUnregister Connection{..}  = routeUnregister <$> readIORef roleInfo
