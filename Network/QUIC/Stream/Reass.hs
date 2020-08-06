{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Reass (
    takeRecvStreamQwithSize
  , putRxStreamData
  , tryReassemble
  ) where

import qualified Data.ByteString as BS

import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Stream.Queue
import Network.QUIC.Stream.Types
import Network.QUIC.Types

----------------------------------------------------------------

getEndOfStream :: Stream -> IO Bool
getEndOfStream Stream{..} = readIORef $ endOfStream streamRecvQ

setEndOfStream :: Stream -> IO ()
setEndOfStream Stream{..} = writeIORef (endOfStream streamRecvQ) True

readPendingData :: Stream -> IO (Maybe ByteString)
readPendingData Stream{..} = readIORef $ pendingData streamRecvQ

writePendingData :: Stream -> ByteString -> IO ()
writePendingData Stream{..} bs = writeIORef (pendingData streamRecvQ) $ Just bs

clearPendingData :: Stream -> IO ()
clearPendingData Stream{..} = writeIORef (pendingData streamRecvQ) Nothing

----------------------------------------------------------------

takeRecvStreamQwithSize :: Stream -> Int -> IO ByteString
takeRecvStreamQwithSize strm siz0 = do
    eos <- getEndOfStream strm
    if eos then
        return ""
      else do
        mb <- readPendingData strm
        case mb of
          Nothing -> do
              b0 <- takeRecvStreamQ strm
              if b0 == "" then do
                  setEndOfStream strm
                  return ""
                else do
                  let len = BS.length b0
                  case len `compare` siz0 of
                      LT -> tryRead (siz0 - len) (b0 :)
                      EQ -> return b0
                      GT -> do
                          let (b1,b2) = BS.splitAt siz0 b0
                          writePendingData strm b2
                          return b1
          Just b0 -> do
              clearPendingData strm
              let len = BS.length b0
              tryRead (siz0 - len) (b0 :)
  where
    tryRead siz build = do
        mb <- tryTakeRecvStreamQ strm
        case mb of
          Nothing -> return $ BS.concat $ build []
          Just b  -> do
              if b == "" then do
                  setEndOfStream strm
                  return $ BS.concat $ build []
                else do
                  let len = BS.length b
                  case len `compare` siz of
                    LT -> tryRead (siz - len) (build . (b :))
                    EQ -> return $ BS.concat $ build [b]
                    GT -> do
                        let (b1,b2) = BS.splitAt siz b
                        writePendingData strm b2
                        return $ BS.concat $ build [b1]

----------------------------------------------------------------
----------------------------------------------------------------

putRxStreamData :: Stream -> RxStreamData -> IO ()
putRxStreamData s rx = do
    (dats,fin1,_) <- tryReassemble s rx
    loop fin1 dats
  where
    loop False []    = return ()
    loop True  []    = putRecvStreamQ s ""
    loop fin1 (d:ds) = do
        when (d /= "") $ putRecvStreamQ s d
        loop fin1 ds

tryReassemble :: Stream -> RxStreamData -> IO ([StreamData], Fin, Bool) -- dup
tryReassemble Stream{}   (RxStreamData "" _  _ False) = return ([], False, False)
tryReassemble Stream{..} (RxStreamData "" off _ True) = do
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    if fin0 then do
        stdoutLogger "Illegal Fin" -- fixme
        return ([], False, False)
      else case off0 `compare` off of
        LT -> do
            let si1 = si0 { streamFin = True }
            writeIORef streamStateRx si1
            return   ([], False, False)
        EQ -> return ([], True,  False) -- would ignore succeeding fragments
        GT -> return ([], False, True)  -- ignoring ""
tryReassemble Stream{..} x@(RxStreamData dat off len False) = do
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    case off0 `compare` off of
      LT -> do
          len0 <- length <$> readIORef streamReass
          atomicModifyIORef'' streamReass (push x)
          len1 <- length <$> readIORef streamReass
          return ([], False, len0 == len1)
      EQ -> do
          let off1 = off0 + len
          xs0 <- readIORef streamReass
          let (dats,xs,off2) = split off1 xs0
          writeIORef streamStateRx si0 { streamOffset = off2 }
          writeIORef streamReass xs
          let fin1 = null xs && fin0
          return (dat:dats, fin1, False)
      GT ->
          return ([], False, True)  -- ignoring
tryReassemble Stream{..} x@(RxStreamData dat off len True) = do
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    let si1 = si0 { streamFin = True }
    if fin0 then do
        stdoutLogger "Illegal Fin" -- fixme
        return ([], False, False)
      else case off0 `compare` off of
        LT -> do
            writeIORef streamStateRx si1
            atomicModifyIORef'' streamReass (push x)
            return ([], False, False)
        EQ -> do
            let off1 = off0 + len
            len0 <- length <$> readIORef streamReass
            writeIORef streamStateRx si1 { streamOffset = off1 }
            len1 <- length <$> readIORef streamReass
            return ([dat], True, len0 == len1) -- would ignore succeeding fragments
        GT ->
            return ([], False, True)  -- ignoring

push :: RxStreamData -> [RxStreamData] -> [RxStreamData]
push x0@(RxStreamData _ off0 len0 _) xs0 = loop xs0
  where
    loop [] = [x0]
    loop xxs@(x@(RxStreamData _ off len _):xs)
      | off0 <  off && off0 + len0 <= off = x0 : xxs
      | off0 <  off                       = xxs -- ignoring
      | off0 == off                       = xxs -- ignoring
      |                off + len <= off0  = x : loop xs
      | otherwise                         = xxs -- ignoring

split :: Offset -> [RxStreamData] -> ([StreamData],[RxStreamData],Offset)
split off0 xs0 = loop off0 xs0 id
  where
    loop off' [] build = (build [], [], off')
    loop off' xxs@(RxStreamData dat off len _ : xs) build
      | off' == off = loop (off + len) xs (build . (dat :))
      | otherwise   = (build [], xxs, off')
