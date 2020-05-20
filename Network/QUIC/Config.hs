{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Config where

import Data.IP
import Network.Socket
import Network.TLS hiding (Version, HostName)
import Network.TLS.QUIC

import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Types

----------------------------------------------------------------

-- | Common configuration.
data Config = Config {
    confVersions       :: [Version] -- ^ Versions in the preferred order.
  , confCiphers        :: [Cipher]
  , confGroups         :: [Group]
  , confParameters     :: Parameters
  , confKeyLog         :: String -> IO ()
  , confDebugLog       :: CID -> String -> IO ()
  , confQLog           :: CID -> String -> IO ()
  , confCredentials    :: Credentials
  }

-- | The default value for common configuration.
defaultConfig :: Config
defaultConfig = Config {
    confVersions       = [Draft27]
                         -- intentionally excluding cipher_TLS13_CHACHA20POLY1305_SHA256 due to cryptonite limitation
  , confCiphers        = supportedCiphers defaultSupported
  , confGroups         = supportedGroups defaultSupported
  , confParameters     = defaultParameters
  , confKeyLog         = \_ -> return ()
  , confDebugLog       = \_ _ -> return ()
  , confQLog           = \_ _ -> return ()
  , confCredentials    = mempty
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
  , scConfig         = defaultConfig
  }
