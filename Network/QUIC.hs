-- https://quicwg.org/base-drafts/

module Network.QUIC (
  -- * APIs
    handshake
  , bye
  , recvData
  , sendData
  , recvData'
  , sendData'
  -- * Types
  , Context
  , ClientConfig(..)
  , defaultClientConfig
  , ServerConfig(..)
  , defaultServerConfig
  , Version(..)
  , CID(..)
  , Parameters(..)
  , defaultParameters
  , exampleParameters
  ) where

import Network.QUIC.Context
import Network.QUIC.Handshake
import Network.QUIC.IO
import Network.QUIC.TLS
import Network.QUIC.Transport
