{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.TLS (
    clientHandshaker,
    serverHandshaker,
) where

import Network.TLS hiding (Version, defaultSupported)
import Network.TLS.QUIC
import System.X509

import Network.QUIC.Config
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Types

sessionManager :: SessionEstablish -> SessionManager
sessionManager establish = noSessionManager{sessionEstablish = establish}

clientHandshaker
    :: QUICCallbacks
    -> ClientConfig
    -> Version
    -> AuthCIDs
    -> SessionEstablish
    -> Bool
    -> IO ()
clientHandshaker callbacks ClientConfig{..} ver myAuthCIDs establish use0RTT = do
    caStore <- if ccValidate then getSystemCertificateStore else return mempty
    tlsQUICClient (cparams caStore) callbacks
  where
    sni = fromMaybe ccServerName ccServerNameOverride
    cparams caStore =
        (defaultParamsClient sni "")
            { clientShared = cshared caStore
            , clientHooks = hook
            , clientSupported = supported
            , clientDebug = debug
            , clientWantSessionResumeList = resumptionSession ccResumption
            , clientUseEarlyData = use0RTT
            , clientUseServerNameIndication = ccUseServerNameIndication
            }
    convTP = onTransportParametersCreated ccHooks
    params = convTP $ setCIDsToParameters myAuthCIDs ccParameters
    convExt = onTLSExtensionCreated ccHooks
    skipValidation = ValidationCache (\_ _ _ -> return ValidationCachePass) (\_ _ _ -> return ())
    cshared caStore =
        defaultShared
            { sharedValidationCache =
                if ccValidate then sharedValidationCache defaultShared else skipValidation
            , sharedCAStore = caStore
            , sharedHelloExtensions = convExt $ parametersToExtensionRaw ver params
            , sharedSessionManager = sessionManager establish
            }
    hook =
        ccTlsHooks
            { onSuggestALPN = (<|>) <$> ccALPN ver <*> onSuggestALPN ccTlsHooks
            , onServerCertificate = ccOnServerCertificate
            }
    supported =
        defaultSupported
            { supportedCiphers = ccCiphers
            , supportedGroups = ccGroups
            }
    debug =
        defaultDebugParams
            { debugKeyLogger = ccKeyLog
            }

parametersToExtensionRaw :: Version -> Parameters -> [ExtensionRaw]
parametersToExtensionRaw ver params = [ExtensionRaw tpId eParams]
  where
    tpId = extensionIDForTtransportParameter ver
    eParams = encodeParameters params

serverHandshaker
    :: QUICCallbacks
    -> ServerConfig
    -> Version
    -> IO Parameters
    -> IO ()
serverHandshaker callbacks ServerConfig{..} ver getParams =
    tlsQUICServer sparams callbacks
  where
    sparams =
        defaultParamsServer
            { serverShared = sshared
            , serverHooks = hook
            , serverSupported = supported
            , serverDebug = debug
            , serverEarlyDataSize = if scUse0RTT then quicMaxEarlyDataSize else 0
            , serverTicketLifetime = scTicketLifetime
            }
    convTP = onTransportParametersCreated scHooks
    convExt = onTLSExtensionCreated scHooks
    sshared =
        defaultShared
            { sharedCredentials = scCredentials
            , sharedSessionManager = scSessionManager
            }
    hook =
        scTlsHooks
            { onALPNClientSuggest = case scALPN of
                Nothing -> onALPNClientSuggest scTlsHooks
                Just io -> Just $ io ver
            , onEncryptedExtensionsCreating = \exts0 -> do
                exts0' <- onEncryptedExtensionsCreating scTlsHooks exts0
                params <- getParams
                let exts = convExt $ parametersToExtensionRaw ver $ convTP params
                return $ exts ++ exts0'
            }
    supported =
        defaultSupported
            { supportedVersions = [TLS13]
            , supportedCiphers = scCiphers
            , supportedGroups = scGroups
            }
    debug =
        defaultDebugParams
            { debugKeyLogger = scKeyLog
            }
