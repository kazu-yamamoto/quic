{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.StreamTable (
    getStreamOffset
  , putInputStream
  , getCryptoOffset
  , putInputCrypto
  ) where

import qualified Data.ByteString as BS
import Data.IORef
import qualified Data.Map.Strict as Map

import Network.QUIC.Connection.Queue
import Network.QUIC.Connection.Types
import Network.QUIC.Imports
import Network.QUIC.Types

getStreamOffset :: Connection -> StreamID -> Int -> IO Offset
getStreamOffset conn sid len = do
    StreamState{..} <- checkStreamTable conn sid
    -- sstx is modified by only sender
    StreamInfo off fin <- readIORef sstx
    writeIORef sstx $ StreamInfo (off + len) fin
    return off

putInputStream :: Connection -> StreamID -> Offset -> StreamData -> Fin -> IO ()
putInputStream conn sid off dat fin = do
    ok <- isFragmentTop conn sid off dat fin
    when ok $ do
        putInput conn $ InpStream sid dat
        when fin $ putInput conn $ InpFin sid

isFragmentTop :: Connection -> StreamID -> Offset -> ByteString -> Bool -> IO Bool
isFragmentTop conn sid off dat fin = do
    StreamState{..} <- checkStreamTable conn sid
    -- ssrx is modified by only sender
    si0@(StreamInfo off0 fin0) <- readIORef ssrx
    if fin && fin0 then do
        putStrLn "Illegal Fin"
        return False
      else do
        let si1 | fin       = si0 { siFin = True }
                | otherwise = si0
            len = BS.length dat
        if off == off0 then do
            let si2 = si1 { siOff = off0 + len }
            writeIORef ssrx si2
            return True
          else do
            writeIORef ssrx si1
            let x = Reassemble dat off len
            modifyIORef' ssreass (push x)
            return True

push :: Reassemble -> [Reassemble] -> [Reassemble]
push x0@(Reassemble _ off0 len0) xs0 = loop xs0
  where
    loop [] = [x0]
    loop xxs@(x@(Reassemble _ off len):xs)
      | off0 <  off = if off0 + len0 <= off then x0 : xxs else xxs -- ignoring
      | off0 == off = xxs -- ignoring
      | otherwise   = if off + len <= off0 then x : loop xs else xxs -- ignoring

checkStreamTable :: Connection -> StreamID -> IO StreamState
checkStreamTable Connection{..} sid = do
    -- reader and sender do not insert the same StreamState
    -- at the same time.
    StreamTable tbl0 <- readIORef streamTable
    case Map.lookup sid tbl0 of
      Nothing -> do
          ss <- newStreamState
          atomicModifyIORef streamTable $ \(StreamTable tbl) ->
            (StreamTable $ Map.insert sid ss tbl, ())
          return ss
      Just ss -> return ss

----------------------------------------------------------------

initialCryptoStreamID,handshakeCryptoStreamID,rtt1CryptoStreamID :: StreamID
initialCryptoStreamID   = -1
handshakeCryptoStreamID = -2
rtt1CryptoStreamID      = -3

toCryptoStreamID :: EncryptionLevel -> StreamID
toCryptoStreamID InitialLevel   = initialCryptoStreamID
toCryptoStreamID RTT0Level      = error "toCryptoStreamID"
toCryptoStreamID HandshakeLevel = handshakeCryptoStreamID
toCryptoStreamID RTT1Level      = rtt1CryptoStreamID

----------------------------------------------------------------

getCryptoOffset :: Connection -> EncryptionLevel -> Int -> IO Offset
getCryptoOffset conn lvl len = getStreamOffset conn (toCryptoStreamID lvl) len

putInputCrypto :: Connection -> EncryptionLevel -> Offset -> StreamData -> IO ()
putInputCrypto conn lvl off cdat = do
    ok <- isFragmentTop conn (toCryptoStreamID lvl) off cdat False
    when ok $ do
        putCrypto conn $ InpHandshake lvl cdat
