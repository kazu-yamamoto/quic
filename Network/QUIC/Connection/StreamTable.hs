{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    getStreamOffset
  , putInputStream
  , getCryptoOffset
  , putInputCrypto
  , getStreamFin
  , setStreamFin
  ) where

import qualified Data.ByteString as BS
import Data.IORef
import qualified Data.IntMap.Strict as Map

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

getStreamFin :: Connection -> StreamId -> IO Fin
getStreamFin conn sid = do
    Stream _ _ StreamState{..} <- checkStreamTable conn sid
    -- sstx is modified by only sender
    StreamInfo _ fin <- readIORef sstx
    return fin

setStreamFin :: Connection -> StreamId -> IO ()
setStreamFin conn sid = do
    Stream _ _ StreamState{..} <- checkStreamTable conn sid
    StreamInfo off _ <- readIORef sstx
    writeIORef sstx $ StreamInfo off True

getStreamOffset :: Connection -> StreamId -> Int -> IO Offset
getStreamOffset conn sid len = do
    Stream _ _ StreamState{..} <- checkStreamTable conn sid
    -- sstx is modified by only sender
    StreamInfo off fin <- readIORef sstx
    writeIORef sstx $ StreamInfo (off + len) fin
    return off

putInputStream :: Connection -> StreamId -> Offset -> StreamData -> Fin -> IO ()
putInputStream conn sid off dat fin = do
    (dats,fin1) <- isFragmentTop conn sid off dat fin
    loop fin1 dats
  where
    loop _    []     = return ()
    loop fin1 [d]    = putInput conn $ InpStream sid d fin1
    loop fin1 (d:ds) = do
        putInput conn $ InpStream sid d False
        loop fin1 ds

isFragmentTop :: Connection -> StreamId -> Offset -> StreamData -> Bool -> IO ([StreamData], Fin)
isFragmentTop conn sid off dat fin = do
    Stream _ _ StreamState{..} <- checkStreamTable conn sid
    -- ssrx is modified by only sender
    si0@(StreamInfo off0 fin0) <- readIORef ssrx
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
            xs0 <- readIORef ssreass
            let (dats,xs,off2) = split off1 xs0
            writeIORef ssrx si1 { siOff = off2 }
            writeIORef ssreass xs
            return (dat:dats, fin1)
          else do
            writeIORef ssrx si1
            let x = Reassemble dat off len
            modifyIORef' ssreass (push x)
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

checkStreamTable :: Connection -> StreamId -> IO Stream
checkStreamTable Connection{..} sid = do
    -- reader and sender do not insert the same StreamState
    -- at the same time.
    StreamTable tbl0 <- readIORef streamTable
    case Map.lookup sid tbl0 of
      Nothing -> do
          s <- newStream sid
          atomicModifyIORef streamTable $ \(StreamTable tbl) ->
            (StreamTable $ Map.insert sid s tbl, ())
          return s
      Just s -> return s

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

getCryptoOffset :: Connection -> EncryptionLevel -> Int -> IO Offset
getCryptoOffset conn lvl len = getStreamOffset conn (toCryptoStreamId lvl) len

putInputCrypto :: Connection -> EncryptionLevel -> Offset -> StreamData -> IO ()
putInputCrypto conn lvl off cdat = do
    (dats, _) <- isFragmentTop conn (toCryptoStreamId lvl) off cdat False
    mapM_ (\d -> putCrypto conn $ InpHandshake lvl d) dats
