module Network.QUIC.Connector where

import Control.Concurrent.STM
import Data.IORef
import Network.QUIC.Types

class Connector a where
    getRole            :: a -> Role
    getEncryptionLevel :: a -> IO EncryptionLevel
    getMaxPacketSize   :: a -> IO Int
    getConnectionState :: a -> IO ConnectionState
    getPacketNumber    :: a -> IO PacketNumber

----------------------------------------------------------------

data ConnState = ConnState {
    role            :: Role
  , connectionState :: TVar ConnectionState
  , packetNumber    :: IORef PacketNumber   -- squeezing three to one
  , encryptionLevel :: TVar EncryptionLevel -- to synchronize
  , maxPacketSize   :: IORef Int
  }

newConnState :: Role -> IO ConnState
newConnState rl =
    ConnState rl <$> newTVarIO Handshaking
                 <*> newIORef 0
                 <*> newTVarIO InitialLevel
                 <*> newIORef defaultQUICPacketSize

----------------------------------------------------------------

data Role = Client | Server deriving (Eq, Show)

isClient :: Connector a => a -> Bool
isClient conn = getRole conn == Client

isServer :: Connector a => a -> Bool
isServer conn = getRole conn == Server

----------------------------------------------------------------

data ConnectionState = Handshaking
                     | ReadyFor0RTT
                     | ReadyFor1RTT
                     | Established
                     | Closing
                     deriving (Eq, Ord, Show)

isConnectionEstablished :: Connector a => a -> IO Bool
isConnectionEstablished conn = do
    st <- getConnectionState conn
    return $ case st of
      Established -> True
      _           -> False

isConnOpen :: Connector a => a -> IO Bool
isConnOpen conn = do
    st <- getConnectionState conn
    return $ case st of
      Closing -> False
      _       -> True
