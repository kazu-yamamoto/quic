{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Config where

import Data.IP
import Network.Socket
import Network.TLS hiding (Version, HostName)
import Network.TLS.Extra.Cipher

import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Transport.Types

data ClientConfig = ClientConfig {
    ccVersion    :: Version
  , ccServerName :: HostName
  , ccPortName   :: ServiceName
  , ccCiphers    :: [Cipher]
  , ccALPN       :: IO (Maybe [ByteString])
  , ccParameters :: Parameters
  }

defaultClientConfig :: ClientConfig
defaultClientConfig = ClientConfig {
    ccVersion    = currentDraft
  , ccServerName = "127.0.0.1"
  , ccPortName   = "13443"
  , ccCiphers    = ciphersuite_strong
  , ccALPN       = return Nothing
  , ccParameters = defaultParameters
  }

----------------------------------------------------------------

data ServerConfig = ServerConfig {
    scVersion      :: Version
  , scAddresses    :: [(IP,PortNumber)]
  , scKey          :: FilePath
  , scCert         :: FilePath
  , scCiphers      :: [Cipher]
  , scALPN         :: Maybe ([ByteString] -> IO ByteString)
  , scParameters   :: Parameters
  , scRequireRetry :: Bool
  }

defaultServerConfig :: ServerConfig
defaultServerConfig = ServerConfig {
    scVersion      = currentDraft
  , scAddresses    = [("127.0.0.1",13443)]
  , scKey          = "serverkey.pem"
  , scCert         = "servercert.pem"
  , scCiphers      = ciphersuite_strong
  , scALPN         = Nothing
  , scParameters   = defaultParameters
  , scRequireRetry = False
  }
