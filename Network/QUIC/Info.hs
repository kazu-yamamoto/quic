module Network.QUIC.Info where

import Data.ByteString ()
import Network.QUIC.Connection
import Network.QUIC.Types
import Network.QUIC.Types.Info
import qualified Network.Socket as NS

----------------------------------------------------------------

-- | Getting information about a connection.
getConnectionInfo :: Connection -> IO ConnectionInfo
getConnectionInfo conn = do
    sock <- getSocket conn
    -- fixme: this is undefined
    mysa <- NS.getSocketName sock
    peersa <- peerSockAddr <$> getPathInfo conn
    mycid <- getMyCID conn
    peercid <- getPeerCID conn
    c <- getCipher conn RTT1Level
    mproto <- getApplicationProtocol conn
    mode <- getTLSMode conn
    r <- getRetried conn
    v <- getVersion conn
    return
        ConnectionInfo
            { version = v
            , cipher = c
            , alpn = mproto
            , handshakeMode = mode
            , retry = r
            , localSockAddr = mysa
            , remoteSockAddr = peersa
            , localCID = mycid
            , remoteCID = peercid
            }

----------------------------------------------------------------

-- | Statistics of a connection.
data ConnectionStats = ConnectionStats
    { txBytes :: Int
    , rxBytes :: Int
    }
    deriving (Eq, Show)

-- | Getting statistics of a connection.
getConnectionStats :: Connection -> IO ConnectionStats
getConnectionStats conn = do
    tx <- getTxBytes conn
    rx <- getRxBytes conn
    return $
        ConnectionStats
            { txBytes = tx
            , rxBytes = rx
            }
