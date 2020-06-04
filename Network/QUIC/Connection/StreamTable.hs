{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    getStream
  , findStream
  , addStream
  , initialRxMaxStreamData
  , setupCryptoStreams
  , getTxCryptoOffset
  , putRxCrypto
  ) where

import Data.IORef

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
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
          putInput conn $ InpNewStream strm
          return strm

findStream :: Connection -> StreamId -> IO (Maybe Stream)
findStream Connection{..} sid = lookupStream sid <$> readIORef streamTable

addStream :: Connection -> StreamId -> IO Stream
addStream conn@Connection{..} sid = do
    strm <- newStream sid shared
    peerParams <- getPeerParameters conn
    let txMaxStreamData | isClient conn = clientInitial sid peerParams
                        | otherwise     = serverInitial sid peerParams
    setTxMaxStreamData strm txMaxStreamData
    let rxMaxStreamData = initialRxMaxStreamData conn sid
    setRxMaxStreamData strm rxMaxStreamData
    atomicModifyIORef' streamTable $ \tbl -> (insertStream sid strm tbl, ())
    return strm

initialRxMaxStreamData :: Connection -> StreamId -> Int
initialRxMaxStreamData conn sid
    | isClient conn = clientInitial sid params
    | otherwise     = serverInitial sid params
  where
    params = getMyParameters conn

clientInitial :: StreamId -> Parameters -> Int
clientInitial sid params
  | isClientInitiatedBidirectional  sid = initialMaxStreamDataBidiRemote params
  | isClientInitiatedUnidirectional sid = initialMaxStreamDataUni        params
  | isServerInitiatedBidirectional  sid = initialMaxStreamDataBidiLocal  params
  | otherwise                           = 0

serverInitial :: StreamId -> Parameters -> Int
serverInitial sid params
  | isServerInitiatedBidirectional  sid = initialMaxStreamDataBidiRemote params
  | isServerInitiatedUnidirectional sid = initialMaxStreamDataUni        params
  | isClientInitiatedBidirectional  sid = initialMaxStreamDataBidiLocal  params
  | otherwise                           = 0

----------------------------------------------------------------

setupCryptoStreams :: Connection -> IO ()
setupCryptoStreams Connection{..} = do
    stbl0 <- readIORef streamTable
    stbl <- insertCryptoStreams stbl0 shared
    writeIORef streamTable stbl

-- FIXME:: deleteCryptoStreams

----------------------------------------------------------------

getTxCryptoOffset :: Connection -> EncryptionLevel -> Int -> IO Offset
getTxCryptoOffset Connection{..} lvl len =
    readIORef streamTable >>= txCryptoOffset lvl len

putRxCrypto :: Connection -> EncryptionLevel -> RxStreamData -> IO ()
putRxCrypto conn@Connection{..} lvl rx = do
    dats <- readIORef streamTable >>= rxCryptoData lvl rx
    mapM_ (putCrypto conn . InpHandshake lvl) dats
