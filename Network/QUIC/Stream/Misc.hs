{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Misc (
    getStreamOffset
  , getStreamTxFin
  , setStreamTxFin
  , isTxClosed
  , isRxClosed
  ) where

import Data.IORef

import Network.QUIC.Imports
import Network.QUIC.Stream.Types
import Network.QUIC.Types

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

isTxClosed :: Stream -> IO Bool
isTxClosed Stream{..} = readIORef $ sharedCloseSent streamShared

isRxClosed :: Stream -> IO Bool
isRxClosed Stream{..} = readIORef $ sharedCloseReceived streamShared

