{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    getStream
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

getStream :: Connection -> StreamId -> IO Stream
getStream conn sid = do
    mstrm <- findStream conn sid
    case mstrm of
      Just strm -> do
          return strm
      Nothing -> do
          strm <- addStream conn sid
          putInput conn $ InpStream strm
          return strm

findStream :: Connection -> StreamId -> IO (Maybe Stream)
findStream Connection{..} sid = lookupStream sid <$> readIORef streamTable

addStream :: Connection -> StreamId -> IO Stream
addStream conn@Connection{..} sid = do
    strm <- newStream conn sid
    peerParams <- getPeerParameters conn
    let txMaxStreamData | isClient conn = clientInitial sid peerParams
                        | otherwise     = serverInitial sid peerParams
    setTxMaxStreamData strm txMaxStreamData
    let rxMaxStreamData = initialRxMaxStreamData conn sid
    setRxMaxStreamData strm rxMaxStreamData
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
  | isClientInitiatedBidirectional  sid = initialMaxStreamDataBidiRemote params
  | isServerInitiatedBidirectional  sid = initialMaxStreamDataBidiLocal  params
  -- intentionally not using isClientInitiatedUnidirectional
  | otherwise                           = initialMaxStreamDataUni        params

serverInitial :: StreamId -> Parameters -> Int
serverInitial sid params
  | isServerInitiatedBidirectional  sid = initialMaxStreamDataBidiRemote params
  | isClientInitiatedBidirectional  sid = initialMaxStreamDataBidiLocal  params
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
