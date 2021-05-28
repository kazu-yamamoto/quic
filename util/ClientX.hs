{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE StrictData #-}

module ClientX where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Network.ByteOrder

import H3
import Network.QUIC.Client

data Aux = Aux {
    auxPath       :: String
  , auxAuthority  :: String
  , auxDebug      :: String -> IO ()
  , auxShow       :: ByteString -> IO ()
  , auxCheckClose :: IO Bool
  }

type Cli = Aux -> Connection -> IO ()

clientHQ :: Cli
clientHQ Aux{..} conn = do
    let cmd = C8.pack ("GET " ++ auxPath ++ "\r\n")
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

clientH3 :: Cli
clientH3 Aux{..} conn = do
    hdrblk <- taglen 1 <$> qpackClient auxPath auxAuthority
    s0 <- stream conn
    s2 <- unidirectionalStream conn
    s6 <- unidirectionalStream conn
    s10 <- unidirectionalStream conn
    -- 0: control, 4 settings
    sendStream s2 (BS.pack [0,4,8,1,80,0,6,128,0,128,0])
    -- 2: from encoder to decoder
    sendStream s6 (BS.pack [2])
    -- 3: from decoder to encoder
    sendStream s10 (BS.pack [3])
    sendStream s0 hdrblk
    shutdownStream s0
    loop s0
  where
    loop s0 = do
        bs <- recvStream s0 1024
        if bs == "" then do
            auxDebug "Fin received"
            closeStream s0
          else do
            auxShow bs
            auxDebug $ show (BS.length bs) ++ " bytes received"
            loop s0

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
