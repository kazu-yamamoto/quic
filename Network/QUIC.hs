{-# LANGUAGE RecordWildCards #-}

-- | This main module provides APIs for QUIC.
module Network.QUIC (
  -- * Running a QUIC client and server
    runQUICClient
  , runQUICServer
  , stopQUICServer
  -- * Basic IO
  , recv
  , send
  , shutdown
  -- * Advanced IO
  , recvStream
  , sendStream
  , shutdownStream
  , isStreamOpen
  -- * Configrations
  , ClientConfig(..)
  , defaultClientConfig
  , ServerConfig(..)
  , defaultServerConfig
  , Config(..)
  , defaultConfig
  -- * Types
  , Connection
  , connDebugLog
  , StreamID
  , Fin
  , Version(..)
  , fromVersion
  , CID
  , fromCID
  -- ** Parameters
  , Parameters(..)
  , defaultParameters
  , exampleParameters
  -- * Information
  , ConnectionInfo(..)
  , getConnectionInfo
  , ResumptionInfo
  , getResumptionInfo
  , isResumptionPossible
  , is0RTTPossible
  -- * Errors
  , QUICError(..)
  ) where

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Core
import Network.QUIC.IO
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Types
