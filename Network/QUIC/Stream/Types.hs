{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Types where

import Control.Concurrent.STM
import Data.IORef

import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

data Chunk = Chunk Stream [StreamData] Fin

type ChunkQ = TQueue Chunk

----------------------------------------------------------------

type WindowSize = Int

data Stream = Stream {
    streamId      :: StreamId -- ^ Getting stream identifier.
  , streamChunkQ  :: ChunkQ
  , streamQ       :: StreamQ
  , streamWindow  :: TVar WindowSize
  , streamStateTx :: IORef StreamState
  , streamStateRx :: IORef StreamState
  , streamReass   :: IORef [Reassemble]
  }

instance Show Stream where
    show s = show $ streamId s

newStream :: StreamId -> ChunkQ -> IO Stream
newStream sid outQ = Stream sid outQ <$> newStreamQ
                                     <*> newTVarIO 65536 -- fixme
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

getStreamOffset :: Stream -> Int -> IO Offset
getStreamOffset Stream{..} len = do
    StreamState off fin <- readIORef streamStateTx
    writeIORef streamStateTx $ StreamState (off + len) fin
    return off

getStreamTxFin :: Stream -> IO Fin
getStreamTxFin Stream{..} = do
    StreamState _ fin <- readIORef streamStateTx
    return fin

setStreamTxFin :: Stream -> IO ()
setStreamTxFin Stream{..} = do
    StreamState off _ <- readIORef streamStateTx
    writeIORef streamStateTx $ StreamState off True

----------------------------------------------------------------

data Reassemble = Reassemble StreamData Offset Int deriving (Eq, Show)
