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

-- | Client configuration.
data ClientConfig = ClientConfig {
    ccVersions      :: [Version] -- ^ Versions in the preferred order.
  , ccCiphers       :: [Cipher]
  , ccGroups        :: [Group]
  , ccParameters    :: Parameters
  , ccKeyLog        :: String -> IO ()
  , ccQLog          :: Maybe FilePath
  , ccCredentials   :: Credentials
  , ccHooks         :: Hooks
  , ccUse0RTT       :: Bool
  -- client original
  , ccServerName    :: HostName -- ^ Used to create a socket and SNI for TLS.
  , ccPortName      :: ServiceName -- ^ Used to create a socket.
  , ccALPN          :: Version -> IO (Maybe [ByteString])
  , ccValidate      :: Bool
  , ccResumption    :: ResumptionInfo
  , ccPacketSize    :: Maybe Int -- ^ QUIC packet size (UDP payload size)
  , ccDebugLog      :: Bool
  , ccAutoMigration :: Bool -- ^ If 'Ture', use a unconnected socket for auto migration.
  }

-- | The default value for client configuration.
defaultClientConfig :: ClientConfig
defaultClientConfig = ClientConfig {
    ccVersions    = [Version1,Draft29]
                         -- intentionally excluding cipher_TLS13_CHACHA20POLY1305_SHA256 due to cryptonite limitation
  , ccCiphers       = supportedCiphers defaultSupported
  , ccGroups        = supportedGroups defaultSupported
  , ccParameters    = defaultParameters
  , ccKeyLog        = \_ -> return ()
  , ccQLog          = Nothing
  , ccCredentials   = mempty
  , ccHooks         = defaultHooks
  , ccUse0RTT       = False
  -- client original
  , ccServerName    = "127.0.0.1"
  , ccPortName      = "4433"
  , ccALPN          = \_ -> return Nothing
  , ccValidate      = False
  , ccResumption    = defaultResumptionInfo
  , ccPacketSize    = Nothing
  , ccDebugLog      = False
  , ccAutoMigration = True
  }

----------------------------------------------------------------

-- | Server configuration.
data ServerConfig = ServerConfig {
    scVersions       :: [Version] -- ^ Versions in the preferred order.
  , scCiphers        :: [Cipher]
  , scGroups         :: [Group]
  , scParameters     :: Parameters
  , scKeyLog         :: String -> IO ()
  , scQLog           :: Maybe FilePath
  , scCredentials    :: Credentials
  , scHooks          :: Hooks
  , scUse0RTT        :: Bool
  -- server original
  , scAddresses      :: [(IP,PortNumber)]
  , scALPN           :: Maybe (Version -> [ByteString] -> IO ByteString)
  , scRequireRetry   :: Bool
  , scSessionManager :: SessionManager
  , scDebugLog       :: Maybe FilePath
  }

-- | The default value for server configuration.
defaultServerConfig :: ServerConfig
defaultServerConfig = ServerConfig {
    scVersions       = [Version1,Draft29]
                         -- intentionally excluding cipher_TLS13_CHACHA20POLY1305_SHA256 due to cryptonite limitation
  , scCiphers        = supportedCiphers defaultSupported
  , scGroups         = supportedGroups defaultSupported
  , scParameters     = defaultParameters
  , scKeyLog         = \_ -> return ()
  , scQLog           = Nothing
  , scCredentials    = mempty
  , scHooks          = defaultHooks
  , scUse0RTT        = False
  -- server original
  , scAddresses      = [("127.0.0.1",4433)]
  , scALPN           = Nothing
  , scRequireRetry   = False
  , scSessionManager = noSessionManager
  , scDebugLog       = Nothing
  }
