{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Misc (
    getStreamOffset
  , getStreamTxFin
  , setStreamTxFin
  , isTxClosed
  , isRxClosed
  , addTxStreamData
  , setTxMaxStreamData
  , waitWindowIsOpen
  ) where

import Control.Concurrent.STM
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

addTxStreamData :: Stream -> Int -> IO ()
addTxStreamData Stream{..} n = atomically $ modifyTVar' streamFlowTx add
  where
    add flow = flow { flowData = flowData flow + n }

setTxMaxStreamData :: Stream -> Int -> IO ()
setTxMaxStreamData Stream{..} n = atomically $ modifyTVar' streamFlowTx
    $ \flow -> flow { flowMaxData = n }

----------------------------------------------------------------

window :: Flow -> Int
window Flow{..} = flowMaxData - flowData

waitWindowIsOpen :: Stream -> Int -> IO ()
waitWindowIsOpen Stream{..} n = do
{-
  xy <- atomically $ do
      x <- readTVar streamFlowTx
      y <- readTVar (sharedConnFlowTx streamShared)
      return (x,y)
  print xy
-}
  atomically $ do
    strmWindow <- window <$> readTVar streamFlowTx
    check (strmWindow >= n)
    connWindow <- window <$> readTVar (sharedConnFlowTx streamShared)
    check (connWindow >= n)
