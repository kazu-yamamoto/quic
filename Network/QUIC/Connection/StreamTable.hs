{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    getStreamOffset
  , putInputStream
  , getCryptoOffset
  , putInputCrypto
  , findStream
  , insertStream
  , insertCryptoStreams
  ) where

import qualified Data.ByteString as BS
import Data.IORef
import qualified Data.IntMap.Strict as Map

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

getStreamOffset :: Stream -> Int -> IO Offset
getStreamOffset Stream{..} len = do
    StreamState off fin <- readIORef streamStateTx
    writeIORef streamStateTx $ StreamState (off + len) fin
    return off

putInputStream :: Connection -> StreamId -> Offset -> StreamData -> Fin -> IO ()
putInputStream conn sid off dat fin = do
    ms <- findStream conn sid
    case ms of
      Just s -> do
          (dats,fin1) <- isFragmentTop s off dat fin
          loop s fin1 dats
      Nothing -> do
          s <- insertStream conn sid
          putInput conn $ InpNewStream s
          (dats,fin1) <- isFragmentTop s off dat fin
          loop s fin1 dats
  where
    loop _ _    []     = return ()
    loop s fin1 [d]    = putStreamData s (d,fin1)
    loop s fin1 (d:ds) = do
        putStreamData s (d,False)
        loop s fin1 ds

isFragmentTop :: Stream -> Offset -> StreamData -> Bool -> IO ([StreamData], Fin)
isFragmentTop Stream{..} off dat fin = do
    -- ssrx is modified by only sender
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    if fin && fin0 then do
        putStrLn "Illegal Fin" -- fixme
        return ([], False)
      else do
        let fin1 = fin0 || fin
            si1 = si0 { siFin = fin1 }
            len = BS.length dat
        if off < off0 then -- ignoring
          return ([], False)
        else if off == off0 then do
            let off1 = off0 + len
            xs0 <- readIORef streamReass
            let (dats,xs,off2) = split off1 xs0
            writeIORef streamStateRx si1 { siOff = off2 }
            writeIORef streamReass xs
            return (dat:dats, fin1)
          else do
            writeIORef streamStateRx si1
            let x = Reassemble dat off len
            modifyIORef' streamReass (push x)
            return ([], False)

push :: Reassemble -> [Reassemble] -> [Reassemble]
push x0@(Reassemble _ off0 len0) xs0 = loop xs0
  where
    loop [] = [x0]
    loop xxs@(x@(Reassemble _ off len):xs)
      | off0 <  off && off0 + len0 <= off = x0 : xxs
      | off0 <  off                       = xxs -- ignoring
      | off0 == off                       = xxs -- ignoring
      |                off + len <= off0  = x : loop xs
      | otherwise                         = xxs -- ignoring

split :: Offset -> [Reassemble] -> ([StreamData],[Reassemble],Offset)
split off0 xs0 = loop off0 xs0 id
  where
    loop off' [] build = (build [], [], off')
    loop off' xxs@(Reassemble dat off len : xs) build
      | off' == off = loop (off + len) xs (build . (dat :))
      | otherwise   = (build [], xxs, off')

findStream :: Connection -> StreamId -> IO (Maybe Stream)
findStream Connection{..} sid = do
    -- reader and sender do not insert the same StreamState
    -- at the same time.
    StreamTable tbl0 <- readIORef streamTable
    return $ Map.lookup sid tbl0

insertStream :: Connection -> StreamId -> IO Stream
insertStream conn@Connection{..} sid = do
    s <- newStream conn sid
    atomicModifyIORef streamTable $ ins s
    return s
  where
    ins s (StreamTable tbl) = (stbl, ())
      where
        stbl = StreamTable $ Map.insert sid s tbl

----------------------------------------------------------------

initialCryptoStreamId,handshakeCryptoStreamId,rtt1CryptoStreamId :: StreamId
initialCryptoStreamId   = -1
handshakeCryptoStreamId = -2
rtt1CryptoStreamId      = -3

toCryptoStreamId :: EncryptionLevel -> StreamId
toCryptoStreamId InitialLevel   = initialCryptoStreamId
toCryptoStreamId RTT0Level      = error "toCryptoStreamId"
toCryptoStreamId HandshakeLevel = handshakeCryptoStreamId
toCryptoStreamId RTT1Level      = rtt1CryptoStreamId

----------------------------------------------------------------

insertCryptoStreams :: Connection -> IO ()
insertCryptoStreams conn = do
    void $ insertStream conn initialCryptoStreamId
    void $ insertStream conn handshakeCryptoStreamId
    void $ insertStream conn rtt1CryptoStreamId

-- FIXME:: deleteCryptoStreams

----------------------------------------------------------------

getCryptoOffset :: Connection -> EncryptionLevel -> Int -> IO Offset
getCryptoOffset conn lvl len = do
    let sid = toCryptoStreamId lvl
    Just s <- findStream conn sid
    getStreamOffset s len

putInputCrypto :: Connection -> EncryptionLevel -> Offset -> StreamData -> IO ()
putInputCrypto conn lvl off cdat = do
    let sid = toCryptoStreamId lvl
    Just s <- findStream conn sid
    (dats, _) <- isFragmentTop s off cdat False
    mapM_ (\d -> putCrypto conn $ InpHandshake lvl d) dats
