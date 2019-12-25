{-# LANGUAGE RecordWildCards #-}

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
  , ConnectionInfo(..)
  , getConnectionInfo
  , ResumptionInfo
  , getResumptionInfo
  , is0RTTPossible
  ) where

import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Core
import Network.QUIC.IO
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Types

import qualified Data.ByteString.Char8 as C8
import Network.TLS hiding (Version)
import Network.TLS.QUIC

data ConnectionInfo = ConnectionInfo {
    cipher :: Cipher
  , alpn :: Maybe ByteString
  , handshakeMode :: HandshakeMode13
  , localCID :: CID
  , remoteCID :: CID
  }

getConnectionInfo :: Connection -> IO ConnectionInfo
getConnectionInfo conn = do
    let mycid = myCID conn
    peercid <- getPeerCID conn
    c <- getCipher conn RTT1Level
    mx <- getApplicationSecretInfo conn
    let (mproto, mode) = case mx of
          Nothing -> (Nothing, FullHandshake)
          Just (ApplicationSecretInfo m p _) -> (p, m)
    return ConnectionInfo {
        cipher = c
      , alpn = mproto
      , handshakeMode = mode
      , localCID = mycid
      , remoteCID = peercid
      }

instance Show ConnectionInfo where
    show ConnectionInfo{..} = "Cipher: " ++ show cipher ++ "\n"
                           ++ "ALPN: " ++ maybe "none" C8.unpack alpn ++ "\n"
                           ++ "Mode: " ++ show handshakeMode ++ "\n"
                           ++ "Local " ++ show localCID ++ "\n"
                           ++ "Remote " ++ show remoteCID
