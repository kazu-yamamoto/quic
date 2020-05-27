{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    putInputStream
  , putInputCrypto
  , addStream
  , setupCryptoStreams
  , getCryptoOffset
  ) where

import Data.IORef

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types
import Network.QUIC.Stream

putInputStream :: Connection -> StreamId -> Offset -> StreamData -> Fin -> IO ()
putInputStream conn sid off dat fin = do
    mstrm <- findStream conn sid
    case mstrm of
      Just strm -> putStreamData strm off dat fin
      Nothing -> do
          strm <- addStream conn sid
          putStreamData strm off dat fin
          putInput conn $ InpNewStream strm

findStream :: Connection -> StreamId -> IO (Maybe Stream)
findStream Connection{..} sid = lookupStream sid <$> readIORef streamTable

addStream :: Connection -> StreamId -> IO Stream
addStream Connection{..} sid = do
    strm <- newStream sid shared
    atomicModifyIORef' streamTable $ \tbl -> (insertStream sid strm tbl, ())
    return strm

----------------------------------------------------------------

setupCryptoStreams :: Connection -> IO ()
setupCryptoStreams Connection{..} = do
    stbl0 <- readIORef streamTable
    stbl <- insertCryptoStreams stbl0 shared
    writeIORef streamTable stbl

-- FIXME:: deleteCryptoStreams

----------------------------------------------------------------

getCryptoOffset :: Connection -> EncryptionLevel -> Int -> IO Offset
getCryptoOffset Connection{..} lvl len =
    readIORef streamTable >>= cryptoOffset lvl len

putInputCrypto :: Connection -> EncryptionLevel -> Offset -> StreamData -> IO ()
putInputCrypto conn@Connection{..} lvl off cdats = do
    dats <- readIORef streamTable >>= getCryptoData lvl off cdats
    mapM_ (putCrypto conn . InpHandshake lvl) dats
