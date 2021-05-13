{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module Network.QUIC.Config where

import Data.IP
import Network.Socket
import Network.TLS hiding (Version, HostName, Hooks)
import Network.TLS.QUIC

import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Stream
import Network.QUIC.Types

----------------------------------------------------------------

-- | Hooks.
data Hooks = Hooks {
    onCloseCompleted :: IO ()
  , onPlainCreated  :: EncryptionLevel -> Plain -> Plain
  , onTransportParametersCreated :: Parameters -> Parameters
  , onTLSExtensionCreated :: [ExtensionRaw] -> [ExtensionRaw]
  , onTLSHandshakeCreated :: [(EncryptionLevel,CryptoData)] -> ([(EncryptionLevel,CryptoData)],Bool)
  , onResetStreamReceived :: Stream -> ApplicationProtocolError -> IO ()
  }

-- | Default hooks.
defaultHooks :: Hooks
defaultHooks = Hooks {
    onCloseCompleted = return ()
  , onPlainCreated  = \_l p -> p
  , onTransportParametersCreated = id
  , onTLSExtensionCreated = id
  , onTLSHandshakeCreated = (, False)
  , onResetStreamReceived = \_ _ -> return ()
  }

----------------------------------------------------------------

-- | Common configuration.
data Config = Config {
    confVersions       :: [Version] -- ^ Versions in the preferred order.
  , confCiphers        :: [Cipher]
  , confGroups         :: [Group]
  , confParameters     :: Parameters
  , confKeyLog         :: String -> IO ()
  , confQLog           :: Maybe FilePath
  , confCredentials    :: Credentials
  , confHooks          :: Hooks
  }

-- | The default value for common configuration.
defaultConfig :: Config
defaultConfig = Config {
    confVersions       = [Version1,Draft32,Draft29]
                         -- intentionally excluding cipher_TLS13_CHACHA20POLY1305_SHA256 due to cryptonite limitation
  , confCiphers        = supportedCiphers defaultSupported
  , confGroups         = supportedGroups defaultSupported
  , confParameters     = defaultParameters
  , confKeyLog         = \_ -> return ()
  , confQLog           = Nothing
  , confCredentials    = mempty
  , confHooks          = defaultHooks
  }

----------------------------------------------------------------

-- | Client configuration.
data ClientConfig = ClientConfig {
    ccServerName :: HostName
  , ccPortName   :: ServiceName
  , ccALPN       :: Version -> IO (Maybe [ByteString])
  , ccValidate   :: Bool
  , ccResumption :: ResumptionInfo
  , ccUse0RTT    :: Bool
  , ccPacketSize :: Maybe Int -- ^ QUIC packet size (UDP payload size)
  , ccDebugLog   :: Bool
  , ccConfig     :: Config
  }

-- | The default value for client configuration.
defaultClientConfig :: ClientConfig
defaultClientConfig = ClientConfig {
    ccServerName = "127.0.0.1"
  , ccPortName   = "4433"
  , ccALPN       = \_ -> return Nothing
  , ccValidate   = False
  , ccResumption = defaultResumptionInfo
  , ccUse0RTT    = False
  , ccPacketSize = Nothing
  , ccDebugLog   = False
  , ccConfig     = defaultConfig
  }

----------------------------------------------------------------

-- | Server configuration.
data ServerConfig = ServerConfig {
    scAddresses      :: [(IP,PortNumber)]
  , scALPN           :: Maybe (Version -> [ByteString] -> IO ByteString)
  , scRequireRetry   :: Bool
  , scSessionManager :: SessionManager
  , scEarlyDataSize  :: Int
  , scDebugLog       :: Maybe FilePath
  , scConfig         :: Config
  }

-- | The default value for server configuration.
defaultServerConfig :: ServerConfig
defaultServerConfig = ServerConfig {
    scAddresses      = [("127.0.0.1",4433)]
  , scALPN           = Nothing
  , scRequireRetry   = False
  , scSessionManager = noSessionManager
  , scEarlyDataSize  = 0
  , scDebugLog       = Nothing
  , scConfig         = defaultConfig
  }
