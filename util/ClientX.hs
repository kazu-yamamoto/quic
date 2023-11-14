{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE StrictData #-}

module ClientX where

import Control.Concurrent
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Network.ByteOrder

import H3
import Network.QUIC

data Aux = Aux {
    auxPath       :: String
  , auxAuthority  :: String
  , auxDebug      :: String -> IO ()
  , auxShow       :: ByteString -> IO ()
  , auxCheckClose :: IO Bool
  }

type Cli = Aux -> Connection -> IO ()

clientHQ :: Int -> Cli
clientHQ n0 aux@Aux{..} conn = loop n0
  where
    cmd = C8.pack ("GET " ++ auxPath ++ "\r\n")
    loop 0 = auxDebug "Connection finished"
    loop 1 = do
        auxDebug "GET"
        get
    loop n = do
        auxDebug "GET"
        get
        threadDelay 100000
        loop (n - 1)
    get = do
        s <- stream conn
        sendStream s cmd
        shutdownStream s
        consume aux s

clientH3 :: Int -> Cli
clientH3 n0 aux@Aux{..} conn = do
    hdrblk <- taglen 1 <$> qpackClient auxPath auxAuthority
    s2 <- unidirectionalStream conn
    s6 <- unidirectionalStream conn
    s10 <- unidirectionalStream conn
    -- 0: control, 4 settings
    sendStream s2 (BS.pack [0,4,8,1,80,0,6,128,0,128,0])
    -- 2: from encoder to decoder
    sendStream s6 (BS.pack [2])
    -- 3: from decoder to encoder
    sendStream s10 (BS.pack [3])
    loop n0 hdrblk
 where
    loop 0 _ = auxDebug "Connection finished"
    loop 1 hdrblk = do
        auxDebug "GET"
        get hdrblk
    loop n hdrblk = do
        auxDebug "GET"
        get hdrblk
        threadDelay 100000
        loop (n - 1) hdrblk
    get hdrblk = do
        s <- stream conn
        sendStream s hdrblk
        shutdownStream s
        consume aux s

consume :: Aux -> Stream -> IO ()
consume aux@Aux{..} s = do
    bs <- recvStream s 1024
    if bs == "" then do
        auxDebug "Fin received"
        closeStream s
      else do
        auxShow bs
        auxDebug $ show (BS.length bs) ++ " bytes received"
        consume aux s

clientPF :: Word64 -> Cli
clientPF n Aux{..} conn = do
    cmd <- withWriteBuffer 8 $ \wbuf -> write64 wbuf n
    s <- stream conn
    sendStream s cmd
    shutdownStream s
    loop s
  where
    loop s = do
        bs <- recvStream s 1024
        if bs == "" then do
            auxDebug "Connection finished"
            closeStream s
          else do
            auxShow bs
            loop s
