{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    putRxStream
  , putRxCrypto
  , findStream
  , addStream
  , setupCryptoStreams
  , getTxCryptoOffset
  , initialRxMaxStreamData
  ) where

import Data.IORef

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Parameters
import Network.QUIC.Stream
import Network.QUIC.Types

putRxStream :: Connection -> StreamId -> RxStreamData
            -> (Stream -> IO ())
            -> IO ()
putRxStream conn sid rx action = do
    mstrm0 <- findStream conn sid
    strm <- case mstrm0 of
      Just strm0 -> do
          putRxStreamData strm0 rx
          return strm0
      Nothing -> do
          strm0 <- addStream conn sid
          putRxStreamData strm0 rx
          putInput conn $ InpNewStream strm0
          return strm0
    action strm

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
    readIORef streamTable >>= cryptoTxOffset lvl len

putRxCrypto :: Connection -> EncryptionLevel -> RxStreamData -> IO ()
putRxCrypto conn@Connection{..} lvl rx = do
    dats <- readIORef streamTable >>= getCryptoData lvl rx
    mapM_ (putCrypto conn . InpHandshake lvl) dats
