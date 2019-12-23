{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Config where

import Data.IP
import Network.Socket
import Network.TLS hiding (Version, HostName)
import Network.TLS.Extra.Cipher

import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Types

----------------------------------------------------------------

data Config = Config {
    confVersion        :: Version
  , confCiphers        :: [Cipher]
  , confGroups         :: [Group]
  , confParameters     :: Parameters
  , confKeyLogging     :: Bool
  }

defaultConfig :: Config
defaultConfig = Config {
    confVersion        = currentDraft
  , confCiphers        = ciphersuite_strong
  , confGroups         = [X25519,P256,P384,P521]
  , confParameters     = defaultParameters
  , confKeyLogging     = False
  }

----------------------------------------------------------------

data ClientConfig = ClientConfig {
    ccServerName :: HostName
  , ccPortName   :: ServiceName
  , ccALPN       :: IO (Maybe [ByteString])
  , ccValidate   :: Bool
  , ccResumption :: ResumptionInfo
  , ccEarlyData  :: Maybe (StreamID,ByteString)
  , ccConfig     :: Config
  }

defaultClientConfig :: ClientConfig
defaultClientConfig = ClientConfig {
    ccServerName = "127.0.0.1"
  , ccPortName   = "13443"
  , ccALPN       = return Nothing
  , ccValidate   = False
  , ccResumption = defaultResumptionInfo
  , ccEarlyData  = Nothing
  , ccConfig     = defaultConfig
  }

----------------------------------------------------------------

data ServerConfig = ServerConfig {
    scAddresses      :: [(IP,PortNumber)]
  , scKey            :: FilePath
  , scCert           :: FilePath
  , scALPN           :: Maybe ([ByteString] -> IO ByteString)
  , scRequireRetry   :: Bool
  , scSessionManager :: SessionManager
  , scEarlyDataSize  :: Int
  , scConfig         :: Config
  }

defaultServerConfig :: ServerConfig
defaultServerConfig = ServerConfig {
    scAddresses      = [("127.0.0.1",13443)]
  , scKey            = "serverkey.pem"
  , scCert           = "servercert.pem"
  , scALPN           = Nothing
  , scRequireRetry   = False
  , scSessionManager = noSessionManager
  , scEarlyDataSize  = 0
  , scConfig         = defaultConfig
  }
