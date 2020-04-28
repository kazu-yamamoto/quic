{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Stream (
    getMyNewStreamId
  , getMyNewUniStreamId
  , getPeerStreamID
  , setPeerStreamID
  , getStreamOffset
  , getStreamFin
  , setStreamFin
  , reassembleStream
  , isFragmentTop
  ) where

import qualified Data.ByteString as BS
import Data.IORef

import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

getMyNewStreamId :: Connection -> IO StreamId
getMyNewStreamId conn = atomicModifyIORef' (myStreamId conn) inc4

getMyNewUniStreamId :: Connection -> IO StreamId
getMyNewUniStreamId conn = atomicModifyIORef' (myUniStreamId conn) inc4

inc4 :: StreamId -> (StreamId,StreamId)
inc4 n = let n' = n + 4 in (n', n)

getPeerStreamID :: Connection -> IO StreamId
getPeerStreamID conn = readIORef $ peerStreamId conn

setPeerStreamID :: Connection -> StreamId -> IO ()
setPeerStreamID conn sid =  writeIORef (peerStreamId conn) sid

getStreamOffset :: Stream -> Int -> IO Offset
getStreamOffset Stream{..} len = do
    StreamState off fin <- readIORef streamStateTx
    writeIORef streamStateTx $ StreamState (off + len) fin
    return off

getStreamFin :: Stream -> IO Fin
getStreamFin Stream{..} = do
    StreamState _ fin <- readIORef streamStateTx
    return fin

setStreamFin :: Stream -> IO ()
setStreamFin Stream{..} = do
    StreamState off _ <- readIORef streamStateTx
    writeIORef streamStateTx $ StreamState off True

----------------------------------------------------------------

reassembleStream :: Stream -> Offset -> StreamData -> Bool -> IO ()
reassembleStream s off dat fin = do
    (dats,fin1) <- isFragmentTop s off dat fin
    loop fin1 dats
  where
    loop _    []     = return ()
    loop fin1 [d]    = do
        putStreamData s d
        when fin1 $ putStreamData s ""
    loop fin1 (d:ds) = do
        putStreamData s d
        loop fin1 ds

isFragmentTop :: Stream -> Offset -> StreamData -> Bool -> IO ([StreamData], Fin)
isFragmentTop Stream{..} off dat fin = do
    -- ssrx is modified by only sender
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    if fin && fin0 then do
        putStrLn "Illegal Fin" -- fixme
        return ([], False)
      else do
        let fin1 = fin0 || fin
            si1 = si0 { streamFin = fin1 }
            len = BS.length dat
        if off < off0 then -- ignoring
          return ([], False)
        else if off == off0 then do
            let off1 = off0 + len
            xs0 <- readIORef streamReass
            let (dats,xs,off2) = split off1 xs0
            writeIORef streamStateRx si1 { streamOffset = off2 }
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
