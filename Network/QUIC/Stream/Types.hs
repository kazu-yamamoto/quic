{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Types (
    Stream (..),
    newStream,
    TxStreamData (..),
    StreamState (..),
    RecvStreamQ (..),
    RxStreamData (..),
    Length,
    syncFinTx,
    waitFinTx,
) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified Data.ByteString as BS
import Network.Control

import {-# SOURCE #-} Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Stream.Frag
import Network.QUIC.Stream.Skew
import qualified Network.QUIC.Stream.Skew as Skew
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
    , streamReass :: IORef (Skew RxStreamData) -- input stream fragments to streamQ
    , streamSyncFinTx :: MVar ()
    }

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
    streamReass     <- newIORef Skew.empty
    streamSyncFinTx <- newEmptyMVar
    return Stream{..}
{- FOURMOLU_ENABLE -}

syncFinTx :: Stream -> IO ()
syncFinTx s = void $ tryPutMVar (streamSyncFinTx s) ()

waitFinTx :: Stream -> IO ()
waitFinTx s = takeMVar $ streamSyncFinTx s

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

instance Frag RxStreamData where
    currOff r = rxstrmOff r
    nextOff r = rxstrmOff r + rxstrmLen r
    shrink off' (RxStreamData bs off len fin) =
        let n = off' - off
            bs' = BS.drop n bs
            len' = len - n
         in RxStreamData
                { rxstrmData = bs'
                , rxstrmOff = off'
                , rxstrmLen = len'
                , rxstrmFin = fin
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
