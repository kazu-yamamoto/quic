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
  , connLog
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
import Network.QUIC.Imports
import Network.QUIC.Packet
import Network.QUIC.Parameters
import Network.QUIC.Types

import qualified Data.ByteString.Char8 as C8
import Network.TLS hiding (Version)
import Network.TLS.QUIC

-- | Information about a connection.
data ConnectionInfo = ConnectionInfo {
    version :: Version
  , cipher :: Cipher
  , alpn :: Maybe ByteString
  , handshakeMode :: HandshakeMode13
  , retry :: Bool
  , localCID :: CID
  , remoteCID :: CID
  }

-- | Getting information about a connection.
getConnectionInfo :: Connection -> IO ConnectionInfo
getConnectionInfo conn = do
    mycid <- getMyCID conn
    peercid <- getPeerCID conn
    c <- getCipher conn RTT1Level
    ApplicationSecretInfo mode mproto _ <- getApplicationSecretInfo conn
    r <- getRetried conn
    v <- getVersion conn
    return ConnectionInfo {
        version = v
      , cipher = c
      , alpn = mproto
      , handshakeMode = mode
      , retry = r
      , localCID = mycid
      , remoteCID = peercid
      }

instance Show ConnectionInfo where
    show ConnectionInfo{..} = "Version: " ++ show version ++ "\n"
                           ++ "Cipher: " ++ show cipher ++ "\n"
                           ++ "ALPN: " ++ maybe "none" C8.unpack alpn ++ "\n"
                           ++ "Mode: " ++ show handshakeMode ++ "\n"
                           ++ "Local " ++ show localCID ++ "\n"
                           ++ "Remote " ++ show remoteCID ++
                           if retry then "\nQUIC retry" else ""
