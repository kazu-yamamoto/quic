{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.TLS.Controller (
    nullClientController
  , clientController
  , serverController
  ) where

import Data.Default.Class
import Data.IORef
import Network.TLS hiding (Version)
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Parameters hiding (diff)
import Network.QUIC.Types

nullClientController :: ClientController
nullClientController _ = return ClientHandshakeDone

sessionManager :: IORef ResumptionInfo -> SessionManager
sessionManager ref = SessionManager {
    sessionEstablish      = establish
  , sessionResume         = \_ -> return Nothing
  , sessionResumeOnlyOnce = \_ -> return Nothing
  , sessionInvalidate     = \_ -> return ()
  }
  where
    establish sid sdata = modifyIORef ref $ \rs -> rs { resumptionSession = Just (sid,sdata) }

clientController:: ClientConfig -> IORef ResumptionInfo -> Bool -> IO ClientController
clientController ClientConfig{..} ref sendEarlyData = newQUICClient cparams
  where
    cparams = (defaultParamsClient ccServerName "") {
        clientShared            = cshared
      , clientHooks             = hook
      , clientSupported         = supported
      , clientDebug             = debug
      , clientWantSessionResume = resumptionSession ccResumption
      , clientEarlyData         = if sendEarlyData then Just "" else Nothing
      }
    eQparams = encodeParametersList $ diffParameters $ confParameters ccConfig
    cshared = def {
        sharedValidationCache = if ccValidate then
                                  def
                                else
                                  ValidationCache (\_ _ _ -> return ValidationCachePass) (\_ _ _ -> return ())
      , sharedExtensions = [ExtensionRaw extensionID_QuicTransportParameters eQparams]
      , sharedSessionManager = sessionManager ref
      }
    hook = def {
        onSuggestALPN = ccALPN
      }
    supported = def {
        supportedVersions = [TLS13]
      , supportedCiphers  = confCiphers ccConfig
      , supportedGroups   = confGroups  ccConfig
      }
    debug = def {
        debugKeyLogger = if confKeyLogging ccConfig then putStrLn else \_ -> return ()
      }

serverController :: ServerConfig
                 -> OrigCID
                 -> IO ServerController
serverController ServerConfig{..} origCID = do
    Right cred <- credentialLoadX509 scCert scKey
    let qparams = case origCID of
          OCFirst _    -> confParameters scConfig
          OCRetry oCID -> (confParameters scConfig) { originalConnectionId = Just oCID }
        eQparams = encodeParametersList $ diffParameters qparams
    let sshared = def {
            sharedCredentials = Credentials [cred]
          , sharedExtensions = [ExtensionRaw extensionID_QuicTransportParameters eQparams]
          , sharedSessionManager = scSessionManager
          }
    let sparams = def {
        serverShared    = sshared
      , serverHooks     = hook
      , serverSupported = supported
      , serverDebug     = debug
      }
    newQUICServer sparams
  where
    hook = def {
        onALPNClientSuggest = scALPN
      }
    supported = def {
        supportedVersions = [TLS13]
      , supportedCiphers  = confCiphers scConfig
      , supportedGroups   = confGroups  scConfig
      }
    debug = def {
        debugKeyLogger = if confKeyLogging scConfig then putStrLn else \_ -> return ()
      }
