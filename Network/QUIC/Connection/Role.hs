{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Role (
    setToken
  , getToken
  , getResumptionInfo
  , setRetried
  , getRetried
  , setResumptionSession
  , setNewToken
  , setRegister
  , getRegister
  , getUnregister
  , setTokenManager
  , getTokenManager
  , setMainThreadId
  , getMainThreadId
  , setCertificateChain
  , getCertificateChain
  ) where

import Control.Concurrent
import qualified Crypto.Token as CT
import Data.X509 (CertificateChain)

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

setToken :: Connection -> Token -> IO ()
setToken Connection{..} token = modifyIORef' roleInfo $ \ci -> ci { clientInitialToken = token }

getToken :: Connection -> IO Token
getToken conn@Connection{..}
  | isClient conn = clientInitialToken <$> readIORef roleInfo
  | otherwise     = return emptyToken

----------------------------------------------------------------

-- | Getting information about resumption.
getResumptionInfo :: Connection -> IO ResumptionInfo
getResumptionInfo Connection{..} = resumptionInfo <$> readIORef roleInfo

----------------------------------------------------------------

setRetried :: Connection -> Bool -> IO ()
setRetried conn@Connection{..} r
  | isClient conn = modifyIORef' roleInfo $ \ci -> ci {
        resumptionInfo = (resumptionInfo ci) { resumptionRetry = r}
        }
  | otherwise     = modifyIORef' roleInfo $ \si -> si { askRetry = r }

getRetried :: Connection -> IO Bool
getRetried conn@Connection{..}
  | isClient conn = resumptionRetry . resumptionInfo <$> readIORef roleInfo
  | otherwise     = askRetry <$> readIORef roleInfo

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

setRegister :: Connection -> (CID -> Connection -> IO ()) -> (CID -> IO ()) -> IO ()
setRegister Connection{..} regisrer unregister = modifyIORef' roleInfo $ \si -> si {
    registerCID = regisrer
  , unregisterCID = unregister
  }

getRegister :: Connection -> IO (CID -> Connection -> IO ())
getRegister Connection{..} = registerCID <$> readIORef roleInfo

getUnregister :: Connection -> IO (CID -> IO ())
getUnregister Connection{..} = unregisterCID <$> readIORef roleInfo

----------------------------------------------------------------

setTokenManager :: Connection -> CT.TokenManager -> IO ()
setTokenManager Connection{..} mgr = modifyIORef' roleInfo $ \si -> si {
    tokenManager = mgr
  }

getTokenManager :: Connection -> IO CT.TokenManager
getTokenManager Connection{..} = tokenManager <$> readIORef roleInfo

----------------------------------------------------------------

setMainThreadId :: Connection -> ThreadId -> IO ()
setMainThreadId Connection{..} tid = modifyIORef' roleInfo $ \si -> si {
    mainThreadId = tid
  }

getMainThreadId :: Connection -> IO ThreadId
getMainThreadId Connection{..} = mainThreadId <$> readIORef roleInfo

----------------------------------------------------------------

setCertificateChain :: Connection -> Maybe CertificateChain -> IO ()
setCertificateChain Connection{..} mcc = modifyIORef' roleInfo $ \si -> si {
    certChain = mcc
  }

getCertificateChain :: Connection -> IO (Maybe CertificateChain)
getCertificateChain Connection{..} = certChain <$> readIORef roleInfo
