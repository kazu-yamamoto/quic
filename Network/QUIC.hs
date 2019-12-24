-- https://quicwg.org/base-drafts/

module Network.QUIC (
  -- * Client
    ClientConfig(..)
  , defaultClientConfig
  , withQUICClient
  , QUICClient
  , connect
  -- * Server
  , ServerConfig(..)
  , defaultServerConfig
  , withQUICServer
  , QUICServer
  , accept
  -- * Config
  , Config(..)
  , defaultConfig
  -- * IO
  , recv
  , send
  , recv'
  , send'
  -- * Closing
  , close
  -- * Types
  , Connection
  , Version(..)
  , StreamID
  -- ** Parameters
  , Parameters(..)
  , defaultParameters
  , exampleParameters
  -- * Information
  , ResumptionInfo
  , getResumptionInfo
  , is0RTTPossible
  ) where

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Core
import Network.QUIC.IO
import Network.QUIC.Parameters
import Network.QUIC.Types
