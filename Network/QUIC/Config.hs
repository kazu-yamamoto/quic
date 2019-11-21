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
  , ccALPN       :: IO (Maybe [ByteString])
  , ccCiphers    :: [Cipher]
  , ccSend       :: ByteString -> IO ()
  , ccRecv       :: IO ByteString
  , ccParameters :: Parameters
  }

defaultClientConfig :: ClientConfig
defaultClientConfig = ClientConfig {
    ccVersion    = currentDraft
  , ccServerName = "127.0.0.1"
  , ccALPN       = return Nothing
  , ccCiphers    = ciphersuite_strong
  , ccSend       = \_ -> return ()
  , ccRecv       = return ""
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
