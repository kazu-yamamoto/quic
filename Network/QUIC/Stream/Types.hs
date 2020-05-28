module Network.QUIC.Stream.Types (
    Chunk(..)
  , ChunkQ
  , Shared(..)
  , newShared
  , Stream(..)
  , newStream
  , StreamQ(..)
  , StreamState(..)
  , Reassemble(..)
  , Flow(..)
  , defaultFlow
  ) where

import Control.Concurrent.STM
import Data.IORef

import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

data Chunk = Chunk Stream [StreamData] Fin

type ChunkQ = TBQueue Chunk

data Shared = Shared {
    sharedCloseSent     :: IORef Bool
  , sharedCloseReceived :: IORef Bool
  , sharedChunkQ        :: ChunkQ
  , sharedConnFlowTx    :: TVar Flow
  }

newShared :: TVar Flow -> IO Shared
newShared tvar = Shared <$> newIORef False <*> newIORef False <*> newTBQueueIO 6 <*> return tvar

----------------------------------------------------------------

data Stream = Stream {
    streamId      :: StreamId -- ^ Getting stream identifier.
  , streamShared  :: Shared
  , streamQ       :: StreamQ
  , streamFlowTx  :: TVar Flow
  , streamFlowRx  :: TVar Flow
  , streamStateTx :: IORef StreamState
  , streamStateRx :: IORef StreamState
  , streamReass   :: IORef [Reassemble]
  }

instance Show Stream where
    show s = show $ streamId s

newStream :: StreamId -> Shared -> IO Stream
newStream sid shrd = Stream sid shrd <$> newStreamQ
                                     <*> newTVarIO defaultFlow
                                     <*> newTVarIO defaultFlow
                                     <*> newIORef emptyStreamState
                                     <*> newIORef emptyStreamState
                                     <*> newIORef []

----------------------------------------------------------------

data StreamQ = StreamQ {
    streamInputQ :: TQueue ByteString
  , pendingData  :: IORef (Maybe ByteString)
  , finReceived  :: IORef Bool
  }

newStreamQ :: IO StreamQ
newStreamQ = StreamQ <$> newTQueueIO <*> newIORef Nothing <*> newIORef False

----------------------------------------------------------------

data StreamState = StreamState {
    streamOffset :: Offset
  , streamFin :: Fin
  } deriving (Eq, Show)

emptyStreamState :: StreamState
emptyStreamState = StreamState 0 False

----------------------------------------------------------------

data Reassemble = Reassemble StreamData Offset Int deriving (Eq, Show)

----------------------------------------------------------------

data Flow = Flow {
    flowData :: Int
  , flowMaxData :: Int
  } deriving (Eq, Show)

defaultFlow :: Flow
defaultFlow = Flow 0 0
