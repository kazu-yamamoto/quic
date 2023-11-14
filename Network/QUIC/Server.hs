-- | This main module provides APIs for QUIC servers.
module Network.QUIC.Server (
    -- * Running a QUIC server
    run,
    stop,

    -- * Configuration
    ServerConfig,
    defaultServerConfig,
    scAddresses,
    scALPN,
    scRequireRetry,
    scUse0RTT,
    scCiphers,
    scGroups,
    scVersions,
    --   , scParameters
    scCredentials,
    scSessionManager,

    -- * Certificate
    clientCertificateChain,
) where

import Data.X509 (CertificateChain)

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Server.Run

----------------------------------------------------------------

-- | Getting a certificate chain of a client.
clientCertificateChain :: Connection -> IO (Maybe CertificateChain)
clientCertificateChain conn
    | isClient conn = return Nothing
    | otherwise = getCertificateChain conn
