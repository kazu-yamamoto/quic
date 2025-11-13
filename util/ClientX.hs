{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module ClientX (
    Misc (..),
    Cli,
    clientHQ,
    clientH3,
    clientPF,
) where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Monad
import qualified Data.ByteString as BS
import Data.IORef
import Network.ByteOrder

import H3
import Network.QUIC

data Misc = Misc
    { miscAuthority :: String
    , miscDebug :: String -> IO ()
    , miscShow :: ByteString -> IO ()
    , miscCheckClose :: IO Bool
    , miscH3NegoDone :: IORef Bool
    }

type Cli = Misc -> [ByteString] -> Connection -> IO ()

clientHQ :: Int -> Cli
clientHQ n0 misc paths conn =
    foldr1 concurrently_ $ map (clientHQ' n0 misc conn) paths

clientHQ' :: Int -> Misc -> Connection -> ByteString -> IO ()
clientHQ' n0 misc@Misc{..} conn path = loop n0
  where
    cmd = "GET " <> path <> "\r\n"
    loop 0 = miscDebug "Connection finished"
    loop 1 = do
        miscDebug "GET"
        get
    loop n = do
        miscDebug "GET"
        get
        threadDelay 100000
        loop (n - 1)
    get = do
        s <- stream conn
        sendStream s cmd
        shutdownStream s
        consume misc s

clientH3 :: Int -> Cli
clientH3 n0 misc paths conn = do
    done <- readIORef $ miscH3NegoDone misc
    unless done $ do
        s2 <- unidirectionalStream conn
        s6 <- unidirectionalStream conn
        s10 <- unidirectionalStream conn
        -- 0: control, 4 settings
        sendStream s2 (BS.pack [0, 4, 8, 1, 80, 0, 6, 128, 0, 128, 0])
        -- 2: from encoder to decoder
        sendStream s6 (BS.pack [2])
        -- 3: from decoder to encoder
        sendStream s10 (BS.pack [3])
        writeIORef (miscH3NegoDone misc) True
    foldr1 concurrently_ $ map (clientH3' n0 misc conn) paths

clientH3' :: Int -> Misc -> Connection -> ByteString -> IO ()
clientH3' n0 misc@Misc{..} conn path = do
    hdrblk <- taglen 1 <$> qpackClient path miscAuthority
    loop n0 hdrblk
  where
    loop 0 _ = miscDebug "Connection finished"
    loop 1 hdrblk = do
        miscDebug "GET"
        get hdrblk
    loop n hdrblk = do
        miscDebug "GET"
        get hdrblk
        threadDelay 100000
        loop (n - 1) hdrblk
    get hdrblk = do
        s <- stream conn
        sendStream s hdrblk
        shutdownStream s
        consume misc s

consume :: Misc -> Stream -> IO ()
consume misc@Misc{..} s = do
    bs <- recvStream s 1024
    if bs == ""
        then do
            miscDebug "Fin received"
            closeStream s
        else do
            miscShow bs
            miscDebug $ show (BS.length bs) ++ " bytes received"
            consume misc s

clientPF :: Word64 -> Cli
clientPF n Misc{..} _paths conn = do
    cmd <- withWriteBuffer 8 $ \wbuf -> write64 wbuf n
    s <- stream conn
    sendStream s cmd
    shutdownStream s
    loop s
  where
    loop s = do
        bs <- recvStream s 1024
        if bs == ""
            then do
                miscDebug "Connection finished"
                closeStream s
            else do
                miscShow bs
                loop s
