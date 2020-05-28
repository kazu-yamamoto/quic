{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.TLS.Handshaker (
    clientHandshaker
  , serverHandshaker
  ) where

import Data.Default.Class
import Network.TLS hiding (Version)
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Parameters
import Network.QUIC.Types

sessionManager :: SessionEstablish -> SessionManager
sessionManager establish = SessionManager {
    sessionEstablish      = establish
  , sessionResume         = \_ -> return Nothing
  , sessionResumeOnlyOnce = \_ -> return Nothing
  , sessionInvalidate     = \_ -> return ()
  }

clientHandshaker :: QUICCallbacks
                 -> ClientConfig
                 -> Version
                 -> AuthCIDs
                 -> SessionEstablish
                 -> Bool
                 -> IO ()
clientHandshaker callbacks ClientConfig{..} ver myAuthCIDs establish use0RTT =
    tlsQUICClient cparams callbacks
  where
    cparams = (defaultParamsClient ccServerName "") {
        clientShared            = cshared
      , clientHooks             = hook
      , clientSupported         = supported
      , clientDebug             = debug
      , clientWantSessionResume = resumptionSession ccResumption
      , clientEarlyData         = if use0RTT then Just "" else Nothing
      }
    qparams = setCIDsToParameters myAuthCIDs $ confParameters ccConfig
    eQparams = encodeParameters qparams
    cshared = def {
        sharedValidationCache = if ccValidate then
                                  def
                                else
                                  ValidationCache (\_ _ _ -> return ValidationCachePass) (\_ _ _ -> return ())
      , sharedHelloExtensions = [ExtensionRaw extensionID_QuicTransportParameters eQparams]
      , sharedSessionManager = sessionManager establish
      }
    hook = def {
        onSuggestALPN = ccALPN ver
      }
    supported = defaultSupported {
        supportedCiphers  = confCiphers ccConfig
      , supportedGroups   = confGroups  ccConfig
      }
    debug = def {
        debugKeyLogger = confKeyLog ccConfig
      }

serverHandshaker :: QUICCallbacks
                 -> ServerConfig
                 -> Version
                 -> AuthCIDs
                 -> IO ()
serverHandshaker callbacks ServerConfig{..} ver myAuthCIDs =
    tlsQUICServer sparams callbacks
  where
    sparams = def {
        serverShared    = sshared
      , serverHooks     = hook
      , serverSupported = supported
      , serverDebug     = debug
      , serverEarlyDataSize = if scEarlyDataSize > 0 then quicMaxEarlyDataSize else 0
      }
    qparams = setCIDsToParameters myAuthCIDs $ confParameters scConfig
    eQparams = encodeParameters qparams
    sshared = def {
            sharedCredentials     = confCredentials scConfig
          , sharedHelloExtensions = [ExtensionRaw extensionID_QuicTransportParameters eQparams]
          , sharedSessionManager  = scSessionManager
          }
    hook = def {
        onALPNClientSuggest = case scALPN of
          Nothing -> Nothing
          Just io -> Just $ io ver
      }
    supported = def {
        supportedVersions = [TLS13]
      , supportedCiphers  = confCiphers scConfig
      , supportedGroups   = confGroups  scConfig
      }
    debug = def {
        debugKeyLogger = confKeyLog scConfig
      }
