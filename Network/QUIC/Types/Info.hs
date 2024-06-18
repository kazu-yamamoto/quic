{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Types.Info where

import qualified Data.ByteString.Char8 as C8
import qualified Network.Socket as NS
import Network.TLS hiding (HandshakeFailed, Version)

import Network.QUIC.Imports
import Network.QUIC.Types.CID
import Network.QUIC.Types.Packet

----------------------------------------------------------------

-- | Information about a connection.
data ConnectionInfo = ConnectionInfo
    { version :: Version
    , cipher :: Cipher
    , alpn :: Maybe ByteString
    , handshakeMode :: HandshakeMode13
    , retry :: Bool
    , localSockAddr :: NS.SockAddr
    , remoteSockAddr :: NS.SockAddr
    , localCID :: CID
    , remoteCID :: CID
    }

instance Show ConnectionInfo where
    show ConnectionInfo{..} =
        "Version: "
            ++ show version
            ++ "\n"
            ++ "Cipher: "
            ++ show cipher
            ++ "\n"
            ++ "ALPN: "
            ++ maybe "none" C8.unpack alpn
            ++ "\n"
            ++ "Mode: "
            ++ show handshakeMode
            ++ "\n"
            ++ "Local CID: "
            ++ show localCID
            ++ "\n"
            ++ "Remote CID: "
            ++ show remoteCID
            ++ "\n"
            ++ "Local SockAddr: "
            ++ show localSockAddr
            ++ "\n"
            ++ "Remote SockAddr: "
            ++ show remoteSockAddr
            ++ if retry then "\nQUIC retry" else ""
