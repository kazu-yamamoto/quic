{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Reass (
    takeStreamData
  , putStreamData
  , getStreamData
  ) where

import qualified Data.ByteString as BS
import Control.Concurrent.STM
import Data.IORef

import Network.QUIC.Imports
import Network.QUIC.Stream.Types
import Network.QUIC.Types

----------------------------------------------------------------

takeStreamData :: Stream -> Int -> IO ByteString
takeStreamData (Stream _ _ StreamQ{..} _ _ _ _) siz0 = do
    fin <- readIORef finReceived
    if fin then
        return ""
      else do
        mb <- readIORef pendingData
        case mb of
          Nothing -> do
              b0 <- atomically $ readTQueue streamInputQ
              if b0 == "" then do
                  writeIORef finReceived True
                  return ""
                else do
                  let len = BS.length b0
                  case len `compare` siz0 of
                      LT -> tryRead (siz0 - len) (b0 :)
                      EQ -> return b0
                      GT -> do
                          let (b1,b2) = BS.splitAt siz0 b0
                          writeIORef pendingData $ Just b2
                          return b1
          Just b0 -> do
              writeIORef pendingData Nothing
              let len = BS.length b0
              tryRead (siz0 - len) (b0 :)
  where
    tryRead siz build = do
        mb <- atomically $ tryReadTQueue streamInputQ
        case mb of
          Nothing -> return $ BS.concat $ build []
          Just b  -> do
              if b == "" then do
                  writeIORef finReceived True
                  return $ BS.concat $ build []
                else do
                  let len = BS.length b
                  case len `compare` siz of
                    LT -> tryRead (siz - len) (build . (b :))
                    EQ -> return $ BS.concat $ build [b]
                    GT -> do
                        let (b1,b2) = BS.splitAt siz b
                        writeIORef pendingData $ Just b2
                        return $ BS.concat $ build [b1]

----------------------------------------------------------------

putStreamData :: Stream -> Offset -> StreamData -> Bool -> IO ()
putStreamData s off dat fin = do
    (dats,fin1) <- getStreamData s off dat fin
    loop fin1 dats
  where
    put = atomically . writeTQueue (streamInputQ $ streamQ s)
    loop False []    = return ()
    loop True  []    = put ""
    loop fin1 (d:ds) = do
        when (d /= "") $ put d
        loop fin1 ds

getStreamData :: Stream -> Offset -> StreamData -> Bool -> IO ([StreamData], Fin)
getStreamData Stream{..} _   "" False = return ([], False)
getStreamData Stream{..} off "" True  = do
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    if fin0 then do
        putStrLn "Illegal Fin" -- fixme
        return ([], False)
      else case off0 `compare` off of
        LT -> do
            let si1 = si0 { streamFin = True }
            writeIORef streamStateRx si1
            return   ([], False)
        EQ -> return ([], True)  -- would ignore succeeding fragments
        GT -> return ([], False) -- ignoring ""
getStreamData Stream{..} off dat False = do
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    let len = BS.length dat
    case off0 `compare` off of
      LT -> do
          let x = Reassemble dat off len
          modifyIORef' streamReass (push x)
          return ([], False)
      EQ -> do
          let off1 = off0 + len
          xs0 <- readIORef streamReass
          let (dats,xs,off2) = split off1 xs0
          writeIORef streamStateRx si0 { streamOffset = off2 }
          writeIORef streamReass xs
          let fin1 = null xs && fin0
          return (dat:dats, fin1)
      GT ->
          return ([], False)  -- ignoring
getStreamData Stream{..} off dat True = do
    si0@(StreamState off0 fin0) <- readIORef streamStateRx
    let len = BS.length dat
        si1 = si0 { streamFin = True }
    if fin0 then do
        putStrLn "Illegal Fin" -- fixme
        return ([], False)
      else case off0 `compare` off of
        LT -> do
            writeIORef streamStateRx si1
            let x = Reassemble dat off len
            modifyIORef' streamReass (push x)
            return ([], False)
        EQ -> do
            let off1 = off0 + len
            writeIORef streamStateRx si1 { streamOffset = off1 }
            return ([dat], True) -- would ignore succeeding fragments
        GT ->
            return ([], False)  -- ignoring

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
