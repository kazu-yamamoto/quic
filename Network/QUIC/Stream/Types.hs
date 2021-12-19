{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Types (
    Stream(..)
  , newStream
  , TxStreamData(..)
  , Flow(..)
  , defaultFlow
  , flowWindow
  , StreamState(..)
  , RecvStreamQ(..)
  , RxStreamData(..)
  , Length
  , syncFinTx
  , waitFinTx
  ) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Data.ByteString as BS

import {-# Source #-} Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Stream.Frag
import Network.QUIC.Stream.Skew
import qualified Network.QUIC.Stream.Skew as Skew
import Network.QUIC.Types

----------------------------------------------------------------

-- | An abstract data type for streams.
data Stream = Stream {
    streamId         :: StreamId -- ^ Getting stream identifier.
  , streamConnection :: Connection
  -- "counter" is equivalent to "offset".
  -- It is duplicated but used for API level flow control.
  , streamFlowTx     :: TVar  Flow        -- counter, maxDax
  , streamFlowRx     :: IORef Flow        -- counter, maxDax
  , streamStateTx    :: IORef StreamState -- offset, fin
  , streamStateRx    :: IORef StreamState -- offset, fin
  , streamRecvQ      :: RecvStreamQ       -- input bytestring
  , streamReass      :: IORef (Skew RxStreamData) -- input stream fragments to streamQ
  , streamSyncFinTx  :: MVar ()
  }

instance Show Stream where
    show s = show $ streamId s

newStream :: Connection -> StreamId -> IO Stream
newStream conn sid = Stream sid conn <$> newTVarIO defaultFlow
                                     <*> newIORef  defaultFlow
                                     <*> newIORef  emptyStreamState
                                     <*> newIORef  emptyStreamState
                                     <*> newRecvStreamQ
                                     <*> newIORef Skew.empty
                                     <*> newEmptyMVar

syncFinTx :: Stream -> IO ()
syncFinTx s = void $ tryPutMVar (streamSyncFinTx s) ()

waitFinTx :: Stream -> IO ()
waitFinTx s = takeMVar $ streamSyncFinTx s

----------------------------------------------------------------

type Length = Int

data TxStreamData = TxStreamData Stream [StreamData] Length Fin

data RxStreamData = RxStreamData {
    rxstrmData :: StreamData
  , rxstrmOff  :: Offset
  , rxstrmLen  :: Length
  , rxstrmFin  :: Fin
  } deriving (Eq, Show)

instance Frag RxStreamData where
    currOff r = rxstrmOff r
    nextOff r = rxstrmOff r + rxstrmLen r
    shrink off'  (RxStreamData bs off len fin) =
        let n = off' - off
            bs'  = BS.drop n bs
            len' = len - n
        in RxStreamData bs' off' len' fin

----------------------------------------------------------------

data Flow = Flow {
    flowData :: Int
  , flowMaxData :: Int
  } deriving (Eq, Show)

defaultFlow :: Flow
defaultFlow = Flow 0 0

flowWindow :: Flow -> Int
flowWindow Flow{..} = flowMaxData - flowData

----------------------------------------------------------------

data StreamState = StreamState {
    streamOffset :: Offset
  , streamFin :: Fin
  } deriving (Eq, Show)

emptyStreamState :: StreamState
emptyStreamState = StreamState 0 False

----------------------------------------------------------------

data RecvStreamQ = RecvStreamQ {
    recvStreamQ :: TQueue ByteString
  , pendingData :: IORef (Maybe ByteString)
  , endOfStream :: IORef Bool
  }

newRecvStreamQ :: IO RecvStreamQ
newRecvStreamQ = RecvStreamQ <$> newTQueueIO <*> newIORef Nothing <*> newIORef False
