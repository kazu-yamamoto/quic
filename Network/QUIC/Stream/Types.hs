{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Types (
    Stream (..),
    newStream,
    TxStreamData (..),
    StreamState (..),
    RxBounds (..),
    emptyRxBounds,
    RecvStreamQ (..),
    RxStreamData (..),
    Reass (..),
    Length,
    syncFinTx,
    waitFinTx,
) where

import Control.Concurrent.STM
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Network.Control

import {-# SOURCE #-} Network.QUIC.Connection.Types (Connection, peerClosedSTM)
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

-- | An abstract data type for streams.
data Stream = Stream
    { streamId :: StreamId
    -- ^ Getting stream identifier.
    , streamConnection :: Connection
    , -- "counter" is equivalent to "offset".
      -- It is duplicated but used for API level flow control.
      streamFlowTx :: TVar TxFlow -- counter, maxDax
    , streamFlowRx :: IORef RxFlow -- counter, maxDax
    , streamStateTx :: IORef StreamState -- offset, fin
    , streamStateRx :: IORef StreamState -- offset, fin
    , streamRecvQ :: RecvStreamQ -- input bytestring
    , streamReass :: IORef Reass
    -- ^ Fragments which cannot be delivered yet
    , streamSyncFinTx :: TMVar ()
    , streamResetTx :: IORef Bool
    -- ^ Whether our sending part has been reset
    , streamResetRx :: IORef (Maybe ApplicationProtocolError)
    -- ^ The error code of a RESET_STREAM from the peer
    , streamReleased :: IORef Bool
    -- ^ Whether we are done with it and have counted it so
    , streamRxBounds :: IORef RxBounds
    -- ^ What has been seen of the stream's end (RFC 9000 Sec 4.5)
    }

-- | What the receiving side has seen of where a stream ends.
data RxBounds = RxBounds
    { rxCounted :: Int
    -- ^ Octets of this stream the connection's flow controller has counted:
    --   every frame taken for it, in order or not
    , rxHighest :: Int
    -- ^ The largest offset plus length seen for it
    , rxFinal :: Maybe Int
    -- ^ Its final size, once that is known
    , rxCredited :: Int
    -- ^ Octets counted against the connection's window on the stream's
    --   behalf, over and above what the application has read
    }
    deriving (Eq, Show)

emptyRxBounds :: RxBounds
emptyRxBounds = RxBounds 0 0 Nothing 0

instance Show Stream where
    show s = show $ streamId s

{- FOURMOLU_DISABLE -}
newStream :: Connection -> Int -> Int -> StreamId -> IO Stream
newStream streamConnection streamId txLim rxLim = do
    streamFlowTx    <- newTVarIO $ newTxFlow txLim
    streamFlowRx    <- newIORef  $ newRxFlow rxLim
    streamStateTx   <- newIORef emptyStreamState
    streamStateRx   <- newIORef emptyStreamState
    streamRecvQ     <- newRecvStreamQ
    streamReass     <- newIORef $ Reass Map.empty Nothing
    streamSyncFinTx <- newEmptyTMVarIO
    streamResetTx   <- newIORef False
    streamResetRx   <- newIORef Nothing
    streamReleased  <- newIORef False
    streamRxBounds  <- newIORef emptyRxBounds
    return Stream{..}
{- FOURMOLU_ENABLE -}

syncFinTx :: Stream -> IO ()
syncFinTx s = void $ atomically $ tryPutTMVar (streamSyncFinTx s) ()

waitFinTx :: Stream -> IO ()
waitFinTx s =
    atomically $
        takeTMVar (streamSyncFinTx s) `orElse` peerClosedSTM (streamConnection s)

----------------------------------------------------------------

type Length = Int

data TxStreamData = TxStreamData Stream [StreamData] Length Fin

data RxStreamData = RxStreamData
    { rxstrmData :: StreamData
    , rxstrmOff :: Offset
    , rxstrmLen :: Length
    , rxstrmFin :: Fin
    }
    deriving (Eq, Show)

-- | What a stream holds past the point it has delivered in order.
data Reass = Reass
    { reassPieces :: Map Offset StreamData
    -- ^ Disjoint, and each starting past the delivered offset
    , reassFin :: Maybe Offset
    -- ^ Where the stream ends, once a FIN is held but not yet delivered
    }

----------------------------------------------------------------

data StreamState = StreamState
    { streamOffset :: Offset
    , streamFin :: Fin
    }
    deriving (Eq, Show)

emptyStreamState :: StreamState
emptyStreamState =
    StreamState
        { streamOffset = 0
        , streamFin = False
        }

----------------------------------------------------------------

data RecvStreamQ = RecvStreamQ
    { recvStreamQ :: TQueue ByteString
    , pendingData :: IORef (Maybe ByteString)
    , endOfStream :: IORef Bool
    }

newRecvStreamQ :: IO RecvStreamQ
newRecvStreamQ = do
    recvStreamQ <- newTQueueIO
    pendingData <- newIORef Nothing
    endOfStream <- newIORef False
    return RecvStreamQ{..}
