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
  , setBaseThreadId
  , getBaseThreadId
  , setCertificateChain
  , getCertificateChain
  , setServerAddr
  , getServerAddr
  ) where

import Control.Concurrent
import qualified Crypto.Token as CT
import Data.X509 (CertificateChain)
import Network.Socket (SockAddr)

import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

setToken :: Connection -> Token -> IO ()
setToken Connection{..} token = atomicModifyIORef'' roleInfo $
    \ci -> ci { clientInitialToken = token }

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
  | isClient conn = atomicModifyIORef'' roleInfo $ \ci -> ci {
        resumptionInfo = (resumptionInfo ci) { resumptionRetry = r}
        }
  | otherwise     = atomicModifyIORef'' roleInfo $ \si -> si { askRetry = r }

getRetried :: Connection -> IO Bool
getRetried conn@Connection{..}
  | isClient conn = resumptionRetry . resumptionInfo <$> readIORef roleInfo
  | otherwise     = askRetry <$> readIORef roleInfo

----------------------------------------------------------------

setResumptionSession :: Connection -> SessionEstablish
setResumptionSession Connection{..} si sd = atomicModifyIORef'' roleInfo $ \ci -> ci {
    resumptionInfo = (resumptionInfo ci) { resumptionSession = Just (si,sd) }
  }

setNewToken :: Connection -> Token -> IO ()
setNewToken Connection{..} token = atomicModifyIORef'' roleInfo $ \ci -> ci {
    resumptionInfo = (resumptionInfo ci) { resumptionToken = token }
  }

----------------------------------------------------------------

setRegister :: Connection -> (CID -> Connection -> IO ()) -> (CID -> IO ()) -> IO ()
setRegister Connection{..} regisrer unregister = atomicModifyIORef'' roleInfo $ \si -> si {
    registerCID = regisrer
  , unregisterCID = unregister
  }

getRegister :: Connection -> IO (CID -> Connection -> IO ())
getRegister Connection{..} = registerCID <$> readIORef roleInfo

getUnregister :: Connection -> IO (CID -> IO ())
getUnregister Connection{..} = unregisterCID <$> readIORef roleInfo

----------------------------------------------------------------

setTokenManager :: Connection -> CT.TokenManager -> IO ()
setTokenManager Connection{..} mgr = atomicModifyIORef'' roleInfo $
    \si -> si { tokenManager = mgr }

getTokenManager :: Connection -> IO CT.TokenManager
getTokenManager Connection{..} = tokenManager <$> readIORef roleInfo

----------------------------------------------------------------

setBaseThreadId :: Connection -> ThreadId -> IO ()
setBaseThreadId Connection{..} tid = atomicModifyIORef'' roleInfo $
    \si -> si { baseThreadId = tid }

getBaseThreadId :: Connection -> IO ThreadId
getBaseThreadId Connection{..} = baseThreadId <$> readIORef roleInfo

----------------------------------------------------------------

setCertificateChain :: Connection -> Maybe CertificateChain -> IO ()
setCertificateChain Connection{..} mcc = atomicModifyIORef'' roleInfo $
    \si -> si { certChain = mcc }

getCertificateChain :: Connection -> IO (Maybe CertificateChain)
getCertificateChain Connection{..} = certChain <$> readIORef roleInfo

----------------------------------------------------------------

setServerAddr :: Connection -> SockAddr -> IO ()
setServerAddr Connection{..} sa = atomicModifyIORef'' roleInfo $
    \si -> si { serverAddr = sa }

getServerAddr :: Connection -> IO SockAddr
getServerAddr Connection{..} = serverAddr <$> readIORef roleInfo
