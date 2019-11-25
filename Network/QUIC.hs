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
  -- * IO
  , recvData
  , sendData
  , recvData'
  , sendData'
  -- * Closing
  , close
  -- * Types
  , Connection
  , Version(..)
  -- ** Parameters
  , Parameters(..)
  , defaultParameters
  , exampleParameters
  ) where

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Core
import Network.QUIC.IO
import Network.QUIC.Parameters
import Network.QUIC.Types
