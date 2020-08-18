module Network.QUIC.Stream.Types (
    Stream(..)
  , newStream
  , TxStreamData(..)
  , SendStreamQ
  , SendBlockedQ
  , Shared(..)
  , newShared
  , Flow(..)
  , defaultFlow
  , StreamState(..)
  , RecvStreamQ(..)
  , RxStreamData(..)
  , Blocked(..)
  , Length
  ) where

import Control.Concurrent.STM

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
  , streamRecvQ   :: RecvStreamQ          -- input bytestring
  , streamReass   :: IORef [RxStreamData] -- input stream fragments to streamQ
  }

instance Show Stream where
    show s = show $ streamId s

newStream :: StreamId -> Shared -> IO Stream
newStream sid shrd = Stream sid shrd <$> newTVarIO defaultFlow
                                     <*> newIORef  defaultFlow
                                     <*> newIORef  emptyStreamState
                                     <*> newIORef  emptyStreamState
                                     <*> newRecvStreamQ
                                     <*> newIORef []

----------------------------------------------------------------

type Length = Int

data TxStreamData = TxStreamData Stream [StreamData] Length Fin
data RxStreamData = RxStreamData StreamData Offset Length Fin deriving (Eq, Show)

type SendStreamQ = TBQueue TxStreamData
type SendBlockedQ = TQueue Blocked

data Shared = Shared {
    sharedCloseSent     :: IORef Bool
  , sharedCloseReceived :: IORef Bool
  , shared1RTTReady     :: IORef Bool
  , sharedSendStreamQ   :: SendStreamQ
  , sharedSendBlockedQ  :: SendBlockedQ
  , sharedConnFlowTx    :: TVar Flow
  }

newShared :: TVar Flow -> IO Shared
newShared tvar = Shared <$> newIORef False
                        <*> newIORef False
                        <*> newIORef False
                        <*> newTBQueueIO 10
                        <*> newTQueueIO
                        <*> return tvar

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
