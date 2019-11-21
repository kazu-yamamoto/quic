{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.TLS.Controller (
    clientController
  , serverController
  ) where

import Data.Default.Class
import Network.TLS hiding (Version)
import Network.TLS.QUIC

import Network.QUIC.Config
import Network.QUIC.Imports
import Network.QUIC.Parameters hiding (diff)
import Network.QUIC.Transport.Types

clientController:: String -> [Cipher]
                -> IO (Maybe [ByteString]) -> ByteString
                -> IO ClientController
clientController serverName ciphers suggestALPN quicParams =
    newQUICClient cparams
  where
    cparams = (defaultParamsClient serverName "") {
        clientShared    = cshared
      , clientHooks     = hook
      , clientSupported = supported
      , clientDebug     = debug
      }
    cshared = def {
        sharedValidationCache = ValidationCache (\_ _ _ -> return ValidationCachePass) (\_ _ _ -> return ())
      , sharedExtensions = [ExtensionRaw extensionID_QuicTransportParameters quicParams]
      }
    hook = def {
        onSuggestALPN = suggestALPN
      }
    supported = def {
        supportedVersions = [TLS13]
      , supportedCiphers  = ciphers
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
