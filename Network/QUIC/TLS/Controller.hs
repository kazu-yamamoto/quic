{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.TLS.Controller (
    nullClientController
  , clientController
  , serverController
  ) where

import Data.Default.Class
import Network.TLS hiding (Version)
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Parameters hiding (diff)
import Network.QUIC.Transport.Types

nullClientController :: ClientController
nullClientController _ = return ClientHandshakeDone

clientController:: ClientConfig -> IO ClientController
clientController ClientConfig{..} = newQUICClient cparams
  where
    cparams = (defaultParamsClient ccServerName "") {
        clientShared    = cshared
      , clientHooks     = hook
      , clientSupported = supported
      , clientDebug     = debug
      }
    eQparams = encodeParametersList $ diffParameters ccParameters
    cshared = def {
        sharedValidationCache = ValidationCache (\_ _ _ -> return ValidationCachePass) (\_ _ _ -> return ())
      , sharedExtensions = [ExtensionRaw extensionID_QuicTransportParameters eQparams]
      }
    hook = def {
        onSuggestALPN = ccALPN
      }
    supported = def {
        supportedVersions = [TLS13]
      , supportedCiphers  = ccCiphers
      }
    debug = def
--    debug = def {
--        debugKeyLogger = putStrLn
--      }

serverController :: ServerConfig
                 -> OrigCID
                 -> IO ServerController
serverController ServerConfig{..} origCID = do
    Right cred <- credentialLoadX509 scCert scKey
    let qparams = case origCID of
          OCFirst _    -> scParameters
          OCRetry oCID -> scParameters { originalConnectionId = Just oCID }
        eQparams = encodeParametersList $ diffParameters qparams
    let sshared = def {
            sharedCredentials = Credentials [cred]
          , sharedExtensions = [ExtensionRaw extensionID_QuicTransportParameters eQparams]
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
      , supportedCiphers  = scCiphers
      }
    debug = def
--    debug = def {
--        debugKeyLogger = putStrLn
--      }
