{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-incomplete-record-updates #-}

module Network.QUIC.Connection.Role (
    setToken,
    getToken,
    getResumptionInfo,
    setRetried,
    getRetried,
    setIncompatibleVN,
    getIncompatibleVN,
    setResumptionSession,
    setNewToken,
    setRegister,
    getRegister,
    getUnregister,
    setTokenManager,
    getTokenManager,
    setBaseThreadId,
    getBaseThreadId,
    setCertificateChain,
    getCertificateChain,
) where

import qualified Crypto.Token as CT
import Data.X509 (CertificateChain)
import UnliftIO.Concurrent

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

setToken :: Connection -> Token -> IO ()
setToken Connection{..} token = atomicModifyIORef'' roleInfo $
    \ci -> ci{clientInitialToken = token}

getToken :: Connection -> IO Token
getToken conn@Connection{..}
    | isClient conn = clientInitialToken <$> readIORef roleInfo
    | otherwise = return emptyToken

----------------------------------------------------------------

-- | Getting information about resumption.
getResumptionInfo :: Connection -> IO ResumptionInfo
getResumptionInfo Connection{..} = resumptionInfo <$> readIORef roleInfo

----------------------------------------------------------------

setRetried :: Connection -> Bool -> IO ()
setRetried conn@Connection{..} r
    | isClient conn = atomicModifyIORef'' roleInfo $ \ci ->
        ci
            { resumptionInfo = (resumptionInfo ci){resumptionRetry = r}
            }
    | otherwise = atomicModifyIORef'' roleInfo $ \si -> si{askRetry = r}

getRetried :: Connection -> IO Bool
getRetried conn@Connection{..}
    | isClient conn = resumptionRetry . resumptionInfo <$> readIORef roleInfo
    | otherwise = askRetry <$> readIORef roleInfo

----------------------------------------------------------------

setIncompatibleVN :: Connection -> Bool -> IO ()
setIncompatibleVN conn@Connection{..} icvn
    | isClient conn = atomicModifyIORef'' roleInfo $ \ci ->
        ci
            { incompatibleVN = icvn
            }
    | otherwise = return ()

getIncompatibleVN :: Connection -> IO Bool
getIncompatibleVN conn@Connection{..}
    | isClient conn = incompatibleVN <$> readIORef roleInfo
    | otherwise = return False

----------------------------------------------------------------

setResumptionSession :: Connection -> SessionEstablish
setResumptionSession conn@Connection{..} si sd = do
    ver <- getVersion conn
    atomicModifyIORef'' roleInfo $ \ci ->
        ci
            { resumptionInfo =
                (resumptionInfo ci)
                    { resumptionVersion = ver
                    , resumptionSession = Just (si, sd)
                    }
            }
    return Nothing

setNewToken :: Connection -> Token -> IO ()
setNewToken conn@Connection{..} token = do
    ver <- getVersion conn
    atomicModifyIORef'' roleInfo $ \ci ->
        ci
            { resumptionInfo =
                (resumptionInfo ci)
                    { resumptionVersion = ver
                    , resumptionToken = token
                    }
            }

----------------------------------------------------------------

setRegister
    :: Connection -> (CID -> Connection -> IO ()) -> (CID -> IO ()) -> IO ()
setRegister Connection{..} regisrer unregister = atomicModifyIORef'' roleInfo $ \si ->
    si
        { registerCID = regisrer
        , unregisterCID = unregister
        }

getRegister :: Connection -> IO (CID -> Connection -> IO ())
getRegister Connection{..} = registerCID <$> readIORef roleInfo

getUnregister :: Connection -> IO (CID -> IO ())
getUnregister Connection{..} = unregisterCID <$> readIORef roleInfo

----------------------------------------------------------------

setTokenManager :: Connection -> CT.TokenManager -> IO ()
setTokenManager Connection{..} mgr = atomicModifyIORef'' roleInfo $
    \si -> si{tokenManager = mgr}

getTokenManager :: Connection -> IO CT.TokenManager
getTokenManager Connection{..} = tokenManager <$> readIORef roleInfo

----------------------------------------------------------------

setBaseThreadId :: Connection -> ThreadId -> IO ()
setBaseThreadId Connection{..} tid = atomicModifyIORef'' roleInfo $
    \si -> si{baseThreadId = tid}

getBaseThreadId :: Connection -> IO ThreadId
getBaseThreadId Connection{..} = baseThreadId <$> readIORef roleInfo

----------------------------------------------------------------

setCertificateChain :: Connection -> Maybe CertificateChain -> IO ()
setCertificateChain Connection{..} mcc = atomicModifyIORef'' roleInfo $
    \si -> si{certChain = mcc}

getCertificateChain :: Connection -> IO (Maybe CertificateChain)
getCertificateChain Connection{..} = certChain <$> readIORef roleInfo
