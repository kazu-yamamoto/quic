{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Reass (
    takeRecvStreamQwithSize
  , putRxStreamData
  , tryReassemble
  ) where

import Data.Sequence (Seq)
import qualified Data.Sequence as Seq
import qualified Data.ByteString as BS

import Network.QUIC.Imports
-- import Network.QUIC.Logger
import Network.QUIC.Stream.Frag
import Network.QUIC.Stream.Misc
import Network.QUIC.Stream.Queue
import qualified Network.QUIC.Stream.Skew as Skew
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

putRxStreamData :: Stream -> RxStreamData -> IO Bool
putRxStreamData s rx@(RxStreamData _ off len _) = do
    lim <- getRxMaxStreamData s
    if len + off > lim then
        return False
      else do
        _ <- tryReassemble s rx put putFin
        return True
  where
    put "" = return ()
    put d  = putRecvStreamQ s d
    putFin = putRecvStreamQ s ""

-- fin of StreamState off fin means see-fin-already.
-- return value indicates duplication
tryReassemble :: Stream -> RxStreamData -> (StreamData -> IO ()) -> IO () -> IO Bool
tryReassemble Stream{}   (RxStreamData "" _  _ False) _ _ = return True
tryReassemble Stream{..} x@(RxStreamData "" off _ True) _ putFin = do
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    let si1 = si0 { streamFin = True }
    if fin0 then do
        -- stdoutLogger "Illegal Fin" -- fixme
        return True
      else case off `compare` off0 of
        LT -> return True
        EQ -> do
            writeIORef streamStateRx si1
            putFin
            return False
        GT -> do
            writeIORef streamStateRx si1
            atomicModifyIORef'' streamReass (Skew.insert x)
            return False
tryReassemble Stream{..} x@(RxStreamData dat off len False) put putFin = do
    si0@(StreamState off0 _) <- readIORef streamStateRx
    case off `compare` off0 of
      LT -> return True
      EQ -> do
          put dat
          loop si0 (off0 + len)
          return False
      GT -> do
          atomicModifyIORef'' streamReass (Skew.insert x)
          return False
  where
    loop si0 xff = do
        mrxs <- atomicModifyIORef' streamReass (Skew.deleteMinIf xff)
        case mrxs of
           Nothing   -> writeIORef streamStateRx si0 { streamOffset = xff }
           Just rxs -> do
               mapM_ (put . rxstrmData) rxs
               let xff1 = nextOff rxs
               if hasFin rxs then do
                   putFin
                 else do
                   loop si0 xff1

tryReassemble Stream{..} x@(RxStreamData dat off len True) put putFin = do
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    let si1 = si0 { streamFin = True }
    if fin0 then do
        -- stdoutLogger "Illegal Fin" -- fixme
        return True
      else case off `compare` off0 of
        LT -> return True
        EQ -> do
            let off1 = off0 + len
            writeIORef streamStateRx si1 { streamOffset = off1 }
            put dat
            putFin
            return False
        GT -> do
            writeIORef streamStateRx si1
            atomicModifyIORef'' streamReass (Skew.insert x)
            return False

hasFin :: Seq RxStreamData -> Bool
hasFin s = case Seq.viewr s of
  Seq.EmptyR -> False
  _ Seq.:> x -> rxstrmFin x
