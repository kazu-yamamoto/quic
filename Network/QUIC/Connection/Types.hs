{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Types where

import Control.Concurrent
import Control.Concurrent.STM
import Data.Hourglass
import Data.IORef
import Data.IntPSQ (IntPSQ)
import qualified Data.IntPSQ as PSQ
import Data.Set (Set)
import qualified Data.Set as Set
import Network.TLS.QUIC
import System.Mem.Weak

import Network.QUIC.Config
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.TLS
import Network.QUIC.Transport.Error
import Network.QUIC.Transport.Types

----------------------------------------------------------------

data Role = Client | Server deriving (Eq, Show)

----------------------------------------------------------------

data ConnectionState = NotOpen | Open | Closing deriving (Eq, Show)

data CloseState = CloseState {
    closeSent     :: Bool
  , closeReceived :: Bool
  } deriving (Eq, Show)

----------------------------------------------------------------

data Segment = S StreamID ByteString
             | H PacketType ByteString Token
             | C PacketType [Frame]
             | E TransportError
             | A
             deriving Show

type InputQ  = TQueue Segment
type OutputQ = TQueue Segment
type RetransQ = IntPSQ ElapsedP Retrans
data Retrans  = Retrans Segment PacketType (Set PacketNumber)

dummySecrets :: TrafficSecrets a
dummySecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

----------------------------------------------------------------

data Connection = Connection {
    role             :: Role
  , myCID            :: CID
  , connSend         :: ByteString -> IO ()
  , connRecv         :: IO ByteString
  , iniSecrets       :: IORef (TrafficSecrets InitialSecret)
  , hndSecrets       :: IORef (TrafficSecrets HandshakeSecret)
  , appSecrets       :: IORef (TrafficSecrets ApplicationSecret)
  , peerParams       :: IORef Parameters
  , peerCID          :: IORef CID
  , usedCipher       :: IORef Cipher
  , negotiatedProto  :: IORef (Maybe ByteString)
  , inputQ           :: InputQ
  , outputQ          :: OutputQ
  , retransQ         :: IORef RetransQ
  -- my packet numbers intentionally using the single space
  , packetNumber     :: IORef PacketNumber
  -- peer's packet numbers
  , iniPacketNumbers :: IORef (Set PacketNumber)
  , hndPacketNumbers :: IORef (Set PacketNumber)
  , appPacketNumbers :: IORef (Set PacketNumber)
  , iniCryptoOffset  :: IORef Offset
  , hndCryptoOffset  :: IORef Offset
  , appCryptoOffset  :: IORef Offset
  , encryptionLevel  :: TVar EncryptionLevel
  , closeState       :: TVar CloseState -- fixme: stream table
  , connectionState  :: TVar ConnectionState -- fixme: stream table
  , threadIds        :: IORef [Weak ThreadId]
  , connClientCntrl  :: IORef ClientController
  }

newConnection :: Role -> CID -> CID -> (ByteString -> IO ()) -> IO ByteString -> TrafficSecrets InitialSecret -> IO Connection
newConnection rl mid peercid send recv isecs =
    Connection rl mid send recv
        <$> newIORef isecs
        <*> newIORef dummySecrets
        <*> newIORef dummySecrets
        <*> newIORef defaultParameters
        <*> newIORef peercid
        <*> newIORef defaultCipher
        <*> newIORef Nothing
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newIORef PSQ.empty
        <*> newIORef 0
        <*> newIORef Set.empty
        <*> newIORef Set.empty
        <*> newIORef Set.empty
        <*> newIORef 0
        <*> newIORef 0
        <*> newIORef 0
        <*> newTVarIO InitialLevel
        <*> newTVarIO (CloseState False False)
        <*> newTVarIO NotOpen
        <*> newIORef []
        <*> newIORef nullClientController

----------------------------------------------------------------

clientConnection :: ClientConfig -> CID -> CID
                 -> (ByteString -> IO ()) -> IO ByteString -> IO Connection
clientConnection ClientConfig{..} myCID peerCID send recv = do
    let isecs = initialSecrets ccVersion peerCID
    newConnection Client myCID peerCID send recv isecs

serverConnection :: ServerConfig -> CID -> CID -> OrigCID -> (ByteString -> IO ()) -> IO ByteString -> IO Connection
serverConnection ServerConfig{..} myCID peerCID origCID send recv = do
    let isecs = case origCID of
          OCFirst oCID -> initialSecrets scVersion oCID
          OCRetry _    -> initialSecrets scVersion myCID
    newConnection Server myCID peerCID send recv isecs

----------------------------------------------------------------

isClient :: Connection -> Bool
isClient Connection{..} = role == Client
