module Network.QUIC.Connector where

import Control.Concurrent.STM
import Data.IORef
import Network.QUIC.Types

class Connector a where
    getRole :: a -> Role
    getEncryptionLevel :: a -> IO EncryptionLevel
    getMaxPacketSize :: a -> IO Int
    getConnectionState :: a -> IO ConnectionState
    getPacketNumber :: a -> IO PacketNumber
    getAlive :: a -> IO Bool

----------------------------------------------------------------

data ConnState = ConnState
    { role :: Role
    , connectionState :: TVar ConnectionState
    , packetNumber :: IORef PacketNumber -- squeezing three to one
    , encryptionLevel :: TVar EncryptionLevel -- to synchronize
    , maxPacketSize :: IORef Int
    , -- Explicitly separated from 'ConnectionState'
      -- It seems that STM triggers a dead-lock if
      -- it is used in the close function of bracket.
      connectionAlive :: IORef Bool
    }

newConnState :: Role -> IO ConnState
newConnState rl =
    ConnState rl
        <$> newTVarIO Handshaking
        <*> newIORef 0
        <*> newTVarIO InitialLevel
        <*> newIORef defaultQUICPacketSize
        <*> newIORef True

----------------------------------------------------------------

data Role = Client | Server deriving (Eq, Show)

isClient :: Connector a => a -> Bool
isClient conn = getRole conn == Client

isServer :: Connector a => a -> Bool
isServer conn = getRole conn == Server

----------------------------------------------------------------

data ConnectionState
    = Handshaking
    | ReadyFor0RTT
    | ReadyFor1RTT
    | Established
    | Closed
    deriving (Eq, Ord, Show)

isConnectionEstablished :: Connector a => a -> IO Bool
isConnectionEstablished conn = do
    st <- getConnectionState conn
    return $ case st of
        Established -> True
        _ -> False
