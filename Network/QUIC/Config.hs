{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module Network.QUIC.Config where

import Data.IP
import Data.X509.CertificateStore (CertificateStore)
import Data.X509.Validation (validateDefault)
import Network.Socket
import Network.TLS hiding (
    Hooks,
    HostName,
    Version,
    defaultHooks,
    defaultSupported,
 )
import Network.TLS.QUIC
import Network.TLS.Extra.Cipher

import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Stream
import Network.QUIC.Types
import Network.QUIC.Types.Info

----------------------------------------------------------------

-- | Hooks.
data Hooks = Hooks
    { onCloseCompleted :: IO ()
    , onPlainCreated :: EncryptionLevel -> Plain -> Plain
    , onTransportParametersCreated :: Parameters -> Parameters
    , onTLSExtensionCreated :: [ExtensionRaw] -> [ExtensionRaw]
    , onTLSHandshakeCreated
        :: [(EncryptionLevel, CryptoData)]
        -> ([(EncryptionLevel, CryptoData)], Bool)
    , onResetStreamReceived :: Stream -> ApplicationProtocolError -> IO ()
    , onServerReady :: IO ()
    , onConnectionEstablished :: ConnectionInfo -> IO ()
    }

-- | Default hooks.
defaultHooks :: Hooks
defaultHooks =
    Hooks
        { onCloseCompleted = return ()
        , onPlainCreated = \_l p -> p
        , onTransportParametersCreated = id
        , onTLSExtensionCreated = id
        , onTLSHandshakeCreated = (,False)
        , onResetStreamReceived = \_ _ -> return ()
        , onServerReady = return ()
        , onConnectionEstablished = \_ -> return ()
        }

defaultCiphers :: [Cipher]
defaultCiphers = [
    cipher13_CHACHA20_POLY1305_SHA256
  , cipher13_AES_256_GCM_SHA384
  , cipher13_AES_128_GCM_SHA256
  ]

----------------------------------------------------------------

-- | Client configuration.
data ClientConfig = ClientConfig
    { ccVersion :: Version
    -- ^ The version to start with.
    , ccVersions :: [Version]
    -- ^ Compatible versions with 'ccVersion' in the preferred order.
    --
    -- Default: @[Version2, Version1]@
    , ccCiphers :: [Cipher]
    -- ^ Cipher candidates defined in TLS 1.3.
    , ccGroups :: [Group]
    -- ^ Key exchange group candidates defined in TLS 1.3.
    , ccParameters :: Parameters
    , ccKeyLog :: String -> IO ()
    , ccQLog :: Maybe FilePath
    , ccCredentials :: Credentials
    -- ^ TLS credentials.
    , ccHooks :: Hooks
    , ccTlsHooks :: ClientHooks
    , ccUse0RTT :: Bool
    -- ^ Use 0-RTT on the 2nd connection if possible.
    -- client original
    --
    -- Default: 'False'
    , ccServerName :: HostName
    -- ^ Used to create a socket and SNI for TLS.
    , ccPortName :: ServiceName
    -- ^ Used to create a socket.
    , ccALPN :: Version -> IO (Maybe [ByteString])
    -- ^ An ALPN provider.
    , ccValidate :: Bool
    -- ^ Authenticating a server based on its certificate.
    --
    -- Default: 'True'
    , ccOnServerCertificate :: OnServerCertificate
    , ccCAStore :: CertificateStore
    , ccResumption :: ResumptionInfo
    -- ^ Use resumption on the 2nd connection if possible.
    , ccPacketSize :: Maybe Int
    -- ^ QUIC packet size (UDP payload size)
    --
    -- Default: 'Nothing'
    , ccDebugLog :: Bool
    , ccSockConnected :: Bool
    -- ^ If 'True', use a connected socket. Otherwise, use a
    -- unconnected socket.
    --
    -- Default: 'False'
    , ccWatchDog :: Bool
    -- ^ If 'True', a watch dog thread is spawned and 'migrate' is
    -- called when network events are observed.
    --
    -- Default: 'False'
    , ccServerNameOverride :: Maybe HostName
    -- ^ Used to specify SNI for TLS intead of `ccServerName`.
    , ccUseServerNameIndication :: Bool
    -- ^ If 'True', SNI is used. Otherwise, the SNI extension is not sent.
    --
    -- Default: 'True'
    }

-- | The default value for client configuration.
defaultClientConfig :: ClientConfig
defaultClientConfig =
    ClientConfig
        { ccVersion = Version1
        , ccVersions = [Version2, Version1]
        , ccCiphers = defaultCiphers
        , ccGroups = supportedGroups defaultSupported
        , ccParameters = defaultParameters
#if MIN_VERSION_tls(2,1,10)
        , ccKeyLog = defaultKeyLogger
#else
        , ccKeyLog = \ ~_ -> return ()
#endif
        , ccQLog = Nothing
        , ccCredentials = mempty
        , ccHooks = defaultHooks
        , ccTlsHooks = defaultClientHooks
        , ccUse0RTT = False
        , -- client original
          ccServerName = "127.0.0.1"
        , ccPortName = "4433"
        , ccALPN = \_ -> return Nothing
        , ccValidate = True
        , ccOnServerCertificate = validateDefault
        , ccCAStore = mempty
        , ccResumption = defaultResumptionInfo
        , ccPacketSize = Nothing
        , ccDebugLog = False
        , ccSockConnected = False
        , ccWatchDog = False
        , ccServerNameOverride = Nothing
        , ccUseServerNameIndication = True
        }

----------------------------------------------------------------

-- | Server configuration.
data ServerConfig = ServerConfig
    { scVersions :: [Version]
    -- ^ Fully-Deployed Versions in the preferred order.
    , scCiphers :: [Cipher]
    -- ^ Cipher candidates defined in TLS 1.3.
    , scGroups :: [Group]
    -- ^ Key exchange group candidates defined in TLS 1.3.
    , scParameters :: Parameters
    , scKeyLog :: String -> IO ()
    , scQLog :: Maybe FilePath
    , scCredentials :: Credentials
    -- ^ Server certificate information.
    , scHooks :: Hooks
    , scTlsHooks :: ServerHooks
    , scUse0RTT :: Bool
    -- ^ Use 0-RTT on the 2nd connection if possible.
    -- server original
    , scAddresses :: [(IP, PortNumber)]
    -- ^ Server addresses assigned to used network interfaces.
    , scALPN :: Maybe (Version -> [ByteString] -> IO ByteString)
    -- ^ ALPN handler.
    , scRequireRetry :: Bool
    -- ^ Requiring QUIC retry.
    , scSessionManager :: SessionManager
    -- ^ A session manager of TLS 1.3.
    , scDebugLog :: Maybe FilePath
    , scTicketLifetime :: Int
    -- ^ A lifetime (in seconds) for TLS session ticket and QUIC token.
    }

-- | The default value for server configuration.
defaultServerConfig :: ServerConfig
defaultServerConfig =
    ServerConfig
        { scVersions = [Version2, Version1]
        , scCiphers = defaultCiphers
        , scGroups = supportedGroups defaultSupported
        , scParameters = defaultParameters
#if MIN_VERSION_tls(2,1,10)
        , scKeyLog = defaultKeyLogger
#else
        , scKeyLog = \ ~_ -> return ()
#endif
        , scQLog = Nothing
        , scCredentials = mempty
        , scHooks = defaultHooks
        , scTlsHooks = defaultServerHooks
        , scUse0RTT = False
        , -- server original
          scAddresses = [("0.0.0.0", 4433), ("::", 4433)]
        , scALPN = Nothing
        , scRequireRetry = False
        , scSessionManager = noSessionManager
        , scDebugLog = Nothing
        , scTicketLifetime = 7200
        }
