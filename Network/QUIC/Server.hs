{-# LANGUAGE PatternSynonyms #-}

-- | This main module provides APIs for QUIC servers.
module Network.QUIC.Server (
  -- * Running a QUIC server
    run
  , stop
  -- * Configuration
  , ServerConfig
  , defaultServerConfig
  , scAddresses
  , scALPN
  , scRequireRetry
  , scUse0RTT
  , scCiphers
  , scGroups
  , scParameters
  , scCredentials
  , scSessionManager
  -- * Parameters
  , Parameters
  , defaultParameters
  -- ** Accessors
  , maxIdleTimeout
  , maxUdpPayloadSize
  , initialMaxData
  , initialMaxStreamDataBidiLocal
  , initialMaxStreamDataBidiRemote
  , initialMaxStreamDataUni
  , initialMaxStreamsBidi
  , initialMaxStreamsUni
  , ackDelayExponent
  , maxAckDelay
  , disableActiveMigration
  , preferredAddress
  , activeConnectionIdLimit
  -- * Types
  , Milliseconds(..)
  -- * Certificate
  , clientCertificateChain
  ) where

import Data.X509 (CertificateChain)

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Parameters
import Network.QUIC.Server.Run
import Network.QUIC.Types

----------------------------------------------------------------

-- | Getting a certificate chain of a client.
clientCertificateChain :: Connection -> IO (Maybe CertificateChain)
clientCertificateChain conn
  | isClient conn = return Nothing
  | otherwise     = getCertificateChain conn
