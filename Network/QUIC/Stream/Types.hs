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
  , Blocked(..)
  , Length
  ) where

import Control.Concurrent.STM
import qualified Data.ByteString as BS

import {-# Source #-} Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Stream.Frag
import Network.QUIC.Types

----------------------------------------------------------------

-- | An abstract data type for streams.
data Stream = Stream {
    streamId         :: StreamId -- ^ Getting stream identifier.
  , streamConnection :: Connection
  -- "counter" is equivalent to "offset".
  -- It is duplicated but used for API level flow control.
  , streamFlowTx     :: TVar  Flow           -- counter, maxDax
  , streamFlowRx     :: IORef Flow           -- counter, maxDax
  , streamStateTx    :: IORef StreamState    -- offset, fin
  , streamStateRx    :: IORef StreamState    -- offset, fin
  , streamRecvQ      :: RecvStreamQ          -- input bytestring
  , streamReass      :: IORef [RxStreamData] -- input stream fragments to streamQ
  }

instance Show Stream where
    show s = show $ streamId s

newStream :: Connection -> StreamId -> IO Stream
newStream conn sid = Stream sid conn <$> newTVarIO defaultFlow
                                     <*> newIORef  defaultFlow
                                     <*> newIORef  emptyStreamState
                                     <*> newIORef  emptyStreamState
                                     <*> newRecvStreamQ
                                     <*> newIORef []

----------------------------------------------------------------

type Length = Int

data TxStreamData = TxStreamData Stream [StreamData] Length Fin

data RxStreamData = RxStreamData StreamData Offset Length Fin deriving (Eq, Show)

instance Frag RxStreamData where
    currOff (RxStreamData _ off _ _)   = off
    nextOff (RxStreamData _ off len _) = off + len
    shrink  (RxStreamData bs off len fin) off' =
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

----------------------------------------------------------------

data Blocked = BothBlocked Stream Int Int
             | ConnBlocked Int
             | StrmBlocked Stream Int
