{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Info where

import qualified Data.ByteString.Char8 as C8
import qualified Network.Socket as NS
import Network.TLS hiding (Version, HandshakeFailed)
import Network.UDP (UDPSocket(..))

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

-- | Information about a connection.
data ConnectionInfo = ConnectionInfo {
    version :: Version
  , cipher :: Cipher
  , alpn :: Maybe ByteString
  , handshakeMode :: HandshakeMode13
  , retry :: Bool
  , localSockAddr :: NS.SockAddr
  , remoteSockAddr :: NS.SockAddr
  , localCID :: CID
  , remoteCID :: CID
  }

-- | Getting information about a connection.
getConnectionInfo :: Connection -> IO ConnectionInfo
getConnectionInfo conn = do
    UDPSocket{..} <- getSocket conn
    mysa <- NS.getSocketName udpSocket
    mycid   <- getMyCID conn
    peercid <- getPeerCID conn
    c <- getCipher conn RTT1Level
    mproto <- getApplicationProtocol conn
    mode <- getTLSMode conn
    r <- getRetried conn
    v <- getVersion conn
    return ConnectionInfo {
        version = v
      , cipher = c
      , alpn = mproto
      , handshakeMode = mode
      , retry = r
      , localSockAddr  = mysa
      , remoteSockAddr = peerSockAddr
      , localCID  = mycid
      , remoteCID = peercid
      }

instance Show ConnectionInfo where
    show ConnectionInfo{..} = "Version: " ++ show version ++ "\n"
                           ++ "Cipher: " ++ show cipher ++ "\n"
                           ++ "ALPN: " ++ maybe "none" C8.unpack alpn ++ "\n"
                           ++ "Mode: " ++ show handshakeMode ++ "\n"
                           ++ "Local CID: " ++ show localCID ++ "\n"
                           ++ "Remote CID: " ++ show remoteCID ++ "\n"
                           ++ "Local SockAddr: " ++ show localSockAddr ++ "\n"
                           ++ "Remote SockAddr: " ++ show remoteSockAddr ++
                           if retry then "\nQUIC retry" else ""

----------------------------------------------------------------

-- | Statistics of a connection.
data ConnectionStats = ConnectionStats {
    txBytes :: Int
  , rxBytes :: Int
  } deriving (Eq, Show)

-- | Getting statistics of a connection.
getConnectionStats :: Connection -> IO ConnectionStats
getConnectionStats conn = do
    tx <- getTxBytes conn
    rx <- getRxBytes conn
    return $ ConnectionStats {
        txBytes = tx
      , rxBytes = rx
      }
