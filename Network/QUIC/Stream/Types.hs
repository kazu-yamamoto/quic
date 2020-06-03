module Network.QUIC.Stream.Types (
    Stream(..)
  , newStream
  , TxStreamData(..)
  , TxStreamDataQ
  , Shared(..)
  , newShared
  , Flow(..)
  , defaultFlow
  , StreamState(..)
  , RxStreamQ(..)
  , RxStreamData(..)
  ) where

import Control.Concurrent.STM
import Data.IORef

import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

data Stream = Stream {
    streamId      :: StreamId -- ^ Getting stream identifier.
  , streamShared  :: Shared
  , streamFlowTx  :: TVar  Flow           -- counter, maxDax
  , streamFlowRx  :: IORef Flow           -- counter, maxDax
  , streamStateTx :: IORef StreamState    -- offset, fin
  , streamStateRx :: IORef StreamState    -- offset, fin
  , streamRxQ     :: RxStreamQ            -- input bytestring
  , streamReass   :: IORef [RxStreamData] -- input stream fragments to streamQ
  }

instance Show Stream where
    show s = show $ streamId s

newStream :: StreamId -> Shared -> IO Stream
newStream sid shrd = Stream sid shrd <$> newTVarIO defaultFlow
                                     <*> newIORef  defaultFlow
                                     <*> newIORef  emptyStreamState
                                     <*> newIORef  emptyStreamState
                                     <*> newRxStreamQ
                                     <*> newIORef []

----------------------------------------------------------------

type Length = Int

data TxStreamData = TxStreamData Stream [StreamData] Length Fin
data RxStreamData = RxStreamData StreamData Offset Length Fin deriving (Eq, Show)

type TxStreamDataQ = TBQueue TxStreamData

data Shared = Shared {
    sharedCloseSent     :: IORef Bool
  , sharedCloseReceived :: IORef Bool
  , shared1RTTReady     :: IORef Bool
  , sharedTxStreamDataQ :: TxStreamDataQ
  , sharedConnFlowTx    :: TVar Flow
  }

newShared :: TVar Flow -> IO Shared
newShared tvar = Shared <$> newIORef False <*> newIORef False <*> newIORef False <*> newTBQueueIO 6 <*> return tvar

----------------------------------------------------------------

data Flow = Flow {
    flowData :: Int
  , flowMaxData :: Int
  } deriving (Eq, Show)

defaultFlow :: Flow
defaultFlow = Flow 0 0

----------------------------------------------------------------

data StreamState = StreamState {
    streamOffset :: Offset
  , streamFin :: Fin
  } deriving (Eq, Show)

emptyStreamState :: StreamState
emptyStreamState = StreamState 0 False

----------------------------------------------------------------

data RxStreamQ = RxStreamQ {
    rxStreamQ   :: TQueue ByteString
  , pendingData :: IORef (Maybe ByteString)
  , finReceived  :: IORef Bool
  }

newRxStreamQ :: IO RxStreamQ
newRxStreamQ = RxStreamQ <$> newTQueueIO <*> newIORef Nothing <*> newIORef False
