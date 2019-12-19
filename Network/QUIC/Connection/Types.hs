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

data ConnectionState = NotOpen | Open | Closing CloseState deriving (Eq, Show)

data CloseState = CloseState {
    closeSent     :: Bool
  , closeReceived :: Bool
  } deriving (Eq, Show)

----------------------------------------------------------------

data Input = InpStream StreamID ByteString
           | InpHandshake EncryptionLevel ByteString Token
           | InpTransportError TransportError FrameType ReasonPhrase
           | InpApplicationError ApplicationError ReasonPhrase
           deriving Show

data Output = OutStream StreamID ByteString
            | OutControl EncryptionLevel [Frame]
            | OutHndClientHello  ByteString (Maybe (StreamID,ByteString))
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
  , threadIds        :: IORef [Weak ThreadId]
  -- Peer
  , peerCID          :: IORef CID
  , peerParams       :: IORef Parameters
  -- Queues
  , inputQ           :: InputQ
  , outputQ          :: OutputQ
  , retransQ         :: IORef RetransQ
  -- State
  , connectionState  :: TVar ConnectionState -- fixme: stream table
  -- my packet numbers intentionally using the single space
  , packetNumber     :: IORef PacketNumber
  -- peer's packet numbers
  , iniPacketNumbers :: IORef (Set PacketNumber)
  , hndPacketNumbers :: IORef (Set PacketNumber)
  , appPacketNumbers :: IORef (Set PacketNumber)
  , iniCryptoOffset  :: IORef Offset
  , hndCryptoOffset  :: IORef Offset
  , appCryptoOffset  :: IORef Offset
  -- TLS
  , usedCipher       :: IORef Cipher
  , connTLSMode      :: IORef HandshakeMode13
  , encryptionLevel  :: TVar EncryptionLevel -- to synchronize
  , negotiatedProto  :: IORef (Maybe ByteString)
  , iniSecrets       :: IORef (TrafficSecrets InitialSecret)
  , hndSecrets       :: IORef (TrafficSecrets HandshakeSecret)
  , appSecrets       :: IORef (TrafficSecrets ApplicationSecret)
  , earlySecret      :: IORef (Maybe (ClientTrafficSecret EarlySecret))
  -- client only
  , connClientCntrl  :: IORef ClientController
  , connToken        :: IORef Token -- new or retry token
  , resumptionInfo   :: IORef ResumptionInfo
  }

newConnection :: Role -> CID -> CID -> SendMany -> Receive -> TrafficSecrets InitialSecret -> IO Connection
newConnection rl myCID peerCID send recv isecs =
    Connection rl myCID send recv
        <$> newIORef []
        -- Peer
        <*> newIORef peerCID
        <*> newIORef defaultParameters
        -- Queues
        <*> newTQueueIO
        <*> newTQueueIO
        <*> newIORef PSQ.empty
        -- State
        <*> newTVarIO NotOpen
        -- my packet numbers
        <*> newIORef 0
        -- peer's packet numberss
        <*> newIORef Set.empty
        <*> newIORef Set.empty
        <*> newIORef Set.empty
        <*> newIORef 0
        <*> newIORef 0
        <*> newIORef 0
        -- TLS
        <*> newIORef defaultCipher
        <*> newIORef FullHandshake
        <*> newTVarIO InitialLevel
        <*> newIORef Nothing
        <*> newIORef isecs
        <*> newIORef dummySecrets
        <*> newIORef dummySecrets
        <*> newIORef Nothing
        -- client only
        <*> newIORef nullClientController
        <*> newIORef emptyToken
        <*> newIORef defaultResumptionInfo

----------------------------------------------------------------

clientConnection :: ClientConfig -> CID -> CID
                 -> SendMany -> Receive -> IO Connection
clientConnection ClientConfig{..} myCID peerCID send recv = do
    let ver = confVersion ccConfig
        isecs = initialSecrets ver peerCID
    newConnection Client myCID peerCID send recv isecs

serverConnection :: ServerConfig -> CID -> CID -> OrigCID
                 -> SendMany -> Receive -> IO Connection
serverConnection ServerConfig{..} myCID peerCID origCID send recv = do
    let ver = confVersion scConfig
        isecs = case origCID of
          OCFirst oCID -> initialSecrets ver oCID
          OCRetry _    -> initialSecrets ver myCID
    newConnection Server myCID peerCID send recv isecs

----------------------------------------------------------------

isClient :: Connection -> Bool
isClient Connection{..} = role == Client
