-- https://quicwg.org/base-drafts/

module Network.QUIC (
  -- * APIs
    connect
  , accept
  , close
  , recvData
  , sendData
  , recvData'
  , sendData'
  , withQUICServer
  , QUICServer
  -- * Types
  , Connection
  , ClientConfig(..)
  , defaultClientConfig
  , ServerConfig(..)
  , defaultServerConfig
  , Version(..)
  , CID
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
import Network.QUIC.TLS
import Network.QUIC.Transport

