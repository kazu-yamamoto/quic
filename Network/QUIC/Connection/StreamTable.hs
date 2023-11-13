{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    createStream
  , findStream
  , addStream
  , delStream
  , initialRxMaxStreamData
  , setupCryptoStreams
  , clearCryptoStream
  , getCryptoStream
  ) where

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Stream
import Network.QUIC.Types

createStream :: Connection -> StreamId -> IO Stream
createStream conn sid = do
      strm <- addStream conn sid
      putInput conn $ InpStream strm
      return strm

findStream :: Connection -> StreamId -> IO (Maybe Stream)
findStream Connection{..} sid = lookupStream sid <$> readIORef streamTable

addStream :: Connection -> StreamId -> IO Stream
addStream conn@Connection{..} sid = do
    strm <- newStream conn sid
    if isClient conn then do
         let clientParams = getMyParameters conn
         setRxMaxStreamData strm $ clientInitial sid clientParams
         serverParams <- getPeerParameters conn
         setTxMaxStreamData strm $ serverInitial sid serverParams
      else do
         let serverParams = getMyParameters conn
         setRxMaxStreamData strm $ serverInitial sid serverParams
         clientParams <- getPeerParameters conn
         setTxMaxStreamData strm $ clientInitial sid clientParams
    atomicModifyIORef'' streamTable $ insertStream sid strm
    return strm

delStream :: Connection -> Stream -> IO ()
delStream Connection{..} strm =
    atomicModifyIORef'' streamTable $ deleteStream $ streamId strm

initialRxMaxStreamData :: Connection -> StreamId -> Int
initialRxMaxStreamData conn sid
    | isClient conn = clientInitial sid params
    | otherwise     = serverInitial sid params
  where
    params = getMyParameters conn

clientInitial :: StreamId -> Parameters -> Int
clientInitial sid params
  | isClientInitiatedBidirectional  sid = initialMaxStreamDataBidiLocal  params
  | isServerInitiatedBidirectional  sid = initialMaxStreamDataBidiRemote params
  -- intentionally not using isServerInitiatedUnidirectional
  | otherwise                           = initialMaxStreamDataUni        params

serverInitial :: StreamId -> Parameters -> Int
serverInitial sid params
  | isServerInitiatedBidirectional  sid = initialMaxStreamDataBidiLocal  params
  | isClientInitiatedBidirectional  sid = initialMaxStreamDataBidiRemote params
  -- intentionally not using isClientInitiatedUnidirectional
  | otherwise                           = initialMaxStreamDataUni        params

----------------------------------------------------------------

setupCryptoStreams :: Connection -> IO ()
setupCryptoStreams conn@Connection{..} = do
    stbl0 <- readIORef streamTable
    stbl <- insertCryptoStreams conn stbl0
    writeIORef streamTable stbl

clearCryptoStream :: Connection -> EncryptionLevel -> IO ()
clearCryptoStream Connection{..} lvl =
    atomicModifyIORef'' streamTable $ deleteCryptoStream lvl

----------------------------------------------------------------

getCryptoStream :: Connection -> EncryptionLevel -> IO (Maybe Stream)
getCryptoStream Connection{..} lvl =
    lookupCryptoStream lvl <$> readIORef streamTable
