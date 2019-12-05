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
import Network.QUIC.Types

----------------------------------------------------------------

data Role = Client | Server deriving (Eq, Show)

----------------------------------------------------------------

data ConnectionState = NotOpen | Open | Closing deriving (Eq, Show)

data CloseState = CloseState {
    closeSent     :: Bool
  , closeReceived :: Bool
  } deriving (Eq, Show)

----------------------------------------------------------------

data Input = InpStream StreamID ByteString
           | InpHandshake EncryptionLevel ByteString Token
           | InpEerror TransportError
           deriving Show

data Output = OutStream StreamID ByteString
            | OutControl EncryptionLevel [Frame]
            | OutHndClientHello0 ByteString (Maybe ByteString)
            | OutHndClientHelloR ByteString (Maybe ByteString) Token
            | OutHndServerHello  ByteString ByteString
            | OutHndServerHelloR ByteString
            | OutHndClientFinished ByteString
            | OutHndServerNST ByteString
            deriving Show

type InputQ  = TQueue Input
type OutputQ = TQueue Output
type RetransQ = IntPSQ ElapsedP Retrans
data Retrans  = Retrans Output EncryptionLevel (Set PacketNumber)

dummySecrets :: TrafficSecrets a
dummySecrets = (ClientTrafficSecret "", ServerTrafficSecret "")

type SendMany = [ByteString] -> IO ()
type Receive  = IO [CryptPacket]

----------------------------------------------------------------

data Connection = Connection {
    role             :: Role
  , myCID            :: CID
  , connSend         :: SendMany
  , connRecv         :: Receive
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

newConnection :: Role -> CID -> CID -> SendMany -> Receive -> TrafficSecrets InitialSecret -> IO Connection
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
                 -> SendMany -> Receive -> IO Connection
clientConnection ClientConfig{..} myCID peerCID send recv = do
    let isecs = initialSecrets ccVersion peerCID
    newConnection Client myCID peerCID send recv isecs

serverConnection :: ServerConfig -> CID -> CID -> OrigCID
                 -> SendMany -> Receive -> IO Connection
serverConnection ServerConfig{..} myCID peerCID origCID send recv = do
    let isecs = case origCID of
          OCFirst oCID -> initialSecrets scVersion oCID
          OCRetry _    -> initialSecrets scVersion myCID
    newConnection Server myCID peerCID send recv isecs

----------------------------------------------------------------

isClient :: Connection -> Bool
isClient Connection{..} = role == Client
