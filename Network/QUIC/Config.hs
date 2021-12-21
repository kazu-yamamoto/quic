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
    ccVersionInfo   :: VersionInfo -- ^ Versions in the preferred order.
  , ccCiphers       :: [Cipher] -- ^ Cipher candidates defined in TLS 1.3.
  , ccGroups        :: [Group] -- ^ Key exchange group candidates defined in TLS 1.3.
  , ccParameters    :: Parameters
  , ccKeyLog        :: String -> IO ()
  , ccQLog          :: Maybe FilePath
  , ccCredentials   :: Credentials -- ^ TLS credentials.
  , ccHooks         :: Hooks
  , ccUse0RTT       :: Bool -- ^ Use 0-RTT on the 2nd connection if possible.
  -- client original
  , ccServerName    :: HostName -- ^ Used to create a socket and SNI for TLS.
  , ccPortName      :: ServiceName -- ^ Used to create a socket.
  , ccALPN          :: Version -> IO (Maybe [ByteString]) -- ^ An ALPN provider.
  , ccValidate      :: Bool -- ^ Authenticating a server based on its certificate.
  , ccResumption    :: ResumptionInfo  -- ^ Use resumption on the 2nd connection if possible.
  , ccPacketSize    :: Maybe Int -- ^ QUIC packet size (UDP payload size)
  , ccDebugLog      :: Bool
  , ccAutoMigration :: Bool -- ^ If 'True', use a unconnected socket for auto migration. Otherwise, use a connected socket.
  }

-- | The default value for client configuration.
defaultClientConfig :: ClientConfig
defaultClientConfig = ClientConfig {
    ccVersionInfo   = defaultVersionInfo
  , ccCiphers       = supportedCiphers defaultSupported
  , ccGroups        = supportedGroups defaultSupported
  , ccParameters    = defaultParameters {
        versionInformation = Just defaultVersionInfo
      }
  , ccKeyLog        = \_ -> return ()
  , ccQLog          = Nothing
  , ccCredentials   = mempty
  , ccHooks         = defaultHooks
  , ccUse0RTT       = False
  -- client original
  , ccServerName    = "127.0.0.1"
  , ccPortName      = "4433"
  , ccALPN          = \_ -> return Nothing
  , ccValidate      = True
  , ccResumption    = defaultResumptionInfo
  , ccPacketSize    = Nothing
  , ccDebugLog      = False
  , ccAutoMigration = False
  }

----------------------------------------------------------------

-- | Server configuration.
data ServerConfig = ServerConfig {
    scVersionInfo    :: VersionInfo -- ^ Versions in the preferred order.
  , scCiphers        :: [Cipher] -- ^ Cipher candidates defined in TLS 1.3.
  , scGroups         :: [Group] -- ^ Key exchange group candidates defined in TLS 1.3.
  , scParameters     :: Parameters
  , scKeyLog         :: String -> IO ()
  , scQLog           :: Maybe FilePath
  , scCredentials    :: Credentials -- ^ Server certificate information.
  , scHooks          :: Hooks
  , scUse0RTT        :: Bool -- ^ Use 0-RTT on the 2nd connection if possible.
  -- server original
  , scAddresses      :: [(IP,PortNumber)] -- ^ Server addresses assigned to used network interfaces.
  , scALPN           :: Maybe (Version -> [ByteString] -> IO ByteString) -- ^ ALPN handler.
  , scRequireRetry   :: Bool -- ^ Requiring QUIC retry.
  , scSessionManager :: SessionManager -- ^ A session manager of TLS 1.3.
  , scDebugLog       :: Maybe FilePath
  }

-- | The default value for server configuration.
defaultServerConfig :: ServerConfig
defaultServerConfig = ServerConfig {
    scVersionInfo    = defaultVersionInfo
  , scCiphers        = supportedCiphers defaultSupported
  , scGroups         = supportedGroups defaultSupported
  , scParameters     = defaultParameters {
        versionInformation = Just defaultVersionInfo
      }
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
