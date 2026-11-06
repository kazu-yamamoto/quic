{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.TLS (
    clientHandshaker,
    serverHandshaker,
) where

import Data.X509.CertificateStore (isEmptyCertificateStore)
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
    caStore <-
        if ccValidate
            then
                if isEmptyCertificateStore ccCAStore
                    then getSystemCertificateStore
                    else return ccCAStore
            else return mempty
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

-- | The parameters a server accepting 0-RTT must not lower (RFC 9000
--   Sec 7.4.1, and RFC 9221 Sec 3 for max_datagram_frame_size).
zeroRTTLimits :: Parameters -> Parameters
zeroRTTLimits p =
    baseParameters
        { activeConnectionIdLimit = activeConnectionIdLimit p
        , initialMaxData = initialMaxData p
        , initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal p
        , initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote p
        , initialMaxStreamDataUni = initialMaxStreamDataUni p
        , initialMaxStreamsBidi = initialMaxStreamsBidi p
        , initialMaxStreamsUni = initialMaxStreamsUni p
        , maxDatagramFrameSize = maxDatagramFrameSize p
        }

-- | Whether the parameters now keep to those remembered.
keeps0RTTLimits :: Parameters -> Parameters -> Bool
keeps0RTTLimits remembered now =
    and
        [ f now >= f remembered
        | f <-
            [ activeConnectionIdLimit
            , initialMaxData
            , initialMaxStreamDataBidiLocal
            , initialMaxStreamDataBidiRemote
            , initialMaxStreamDataUni
            , initialMaxStreamsBidi
            , initialMaxStreamsUni
            , maxDatagramFrameSize
            ]
        ]

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
            { serverWantClientCert = scWantClientCert
            , serverShared = sshared
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
            , sharedSessionManager = mgr
            }
    -- RFC 9000 Sec 7.4.1: what 0-RTT is held to is kept with the session,
    -- and 0-RTT is refused if the server now allows less.
    mgr =
        scSessionManager
            { sessionEstablish = \sid sdata -> do
                remembered <- zeroRTTLimits <$> getParams
                sessionEstablish scSessionManager sid $
                    sdata{sessionAppData = Just $ encodeParameters remembered}
            }
    accept0RTT sdata = do
        ok <- onAccept0RTT scTlsHooks sdata
        now <- getParams
        return $ case sessionAppData sdata >>= decodeParameters of
            Just remembered -> ok && keeps0RTTLimits remembered now
            Nothing -> False
    hook =
        scTlsHooks
            { onAccept0RTT = accept0RTT
            , onALPNClientSuggest = case scALPN of
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
            , supportedGroupsTLS13 = scGroupsTLS13
            }
    debug =
        defaultDebugParams
            { debugKeyLogger = scKeyLog
            }
