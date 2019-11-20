-- https://quicwg.org/base-drafts/

module Network.QUIC (
  -- * Server
    ServerConfig(..)
  , defaultServerConfig
  , withQUICServer
  , QUICServer
  , accept
  -- * Client
  , ClientConfig(..)
  , defaultClientConfig
  , connect
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
import Network.QUIC.Handshake
import Network.QUIC.IO
import Network.QUIC.Parameters
import Network.QUIC.Route
import Network.QUIC.Transport

