{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module ServerX where

import Control.Concurrent
import Control.Monad
import qualified Data.ByteString as BS
import Data.ByteString.Builder
import Network.ByteOrder
import qualified UnliftIO.Exception as E

import H3
import Network.QUIC
import Network.QUIC.Internal

serverHQ :: Connection -> IO ()
serverHQ conn = connDebugLog conn "Connection terminated" `onE` body
  where
    body = forever $ do
        s <- acceptStream conn
        consume conn s
        let sid = streamId s
        when (isClientInitiatedBidirectional sid) $ do
            sendStream s html
            closeStream s

serverH3 :: Connection -> IO ()
serverH3 conn =
    connDebugLog conn "Connection terminated" `onE` do
        s3 <- unidirectionalStream conn
        s7 <- unidirectionalStream conn
        s11 <- unidirectionalStream conn
        -- 0: control, 4 settings
        sendStream s3 (BS.pack [0, 4, 8, 1, 80, 0, 6, 128, 0, 128, 0])
        -- 2: from encoder to decoder
        sendStream s7 (BS.pack [2])
        -- 3: from decoder to encoder
        sendStream s11 (BS.pack [3])
        hdrblock <- taglen 1 <$> qpackServer
        let bdyblock = taglen 0 html
            hdrbdy = [hdrblock, bdyblock]
        loop hdrbdy
  where
    loop hdrbdy = do
        s <- acceptStream conn
        void . forkIO $ do
            consume conn s
            let sid = streamId s
            when (isClientInitiatedBidirectional sid) $ do
                sendStreamMany s hdrbdy
                closeStream s
        loop hdrbdy

serverPF :: Connection -> IO ()
serverPF conn =
    connDebugLog conn "Connection terminated" `onE` do
        s <- acceptStream conn
        let sid = streamId s
        when (isClientInitiatedBidirectional sid) $ do
            bs <- recvStream s 8
            n <- withReadBuffer bs read64
            loop s n
            closeStream s
  where
    bs1024 = BS.replicate 1024 65
    loop _ 0 = return ()
    loop s n
        | n < 1024 = sendStream s $ BS.replicate (fromIntegral n) 65
        | otherwise = do
            sendStream s bs1024
            loop s (n - 1024)

consume :: Connection -> Stream -> IO ()
consume conn s = loop
  where
    loop = do
        bs <- recvStream s 1024
        if bs == ""
            then connDebugLog conn "FIN received"
            else do
                connDebugLog conn $ byteString bs
                loop

onE :: IO b -> IO a -> IO a
h `onE` b = b `E.onException` h
