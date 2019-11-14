{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Control.Exception as E
import Control.Monad
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import Network.Run.UDP
import Network.Socket hiding (Stream)
import qualified Network.Socket.ByteString as NSB
import System.Environment

import Network.QUIC

main :: IO ()
main = do
    [serverName,port] <- getArgs
    runUDPClient serverName port $ quicClient serverName

quicClient :: String -> Socket -> SockAddr -> IO ()
quicClient serverName s peerAddr = do
    conf <- makeConf
    E.bracket (handshake conf) bye client
  where
    client ctx = do
        sendData ctx "GET /index.html\r\n"
        recvData ctx >>= C8.putStr
    makeConf = do
        ref <- newIORef peerAddr
        let recv = do
                (bs, peer) <- NSB.recvFrom s 2048
                writeIORef ref peer
                return bs
            send bs = do
                peer <- readIORef ref
                void $ NSB.sendTo s bs peer
        return defaultClientConfig {
                ccVersion    = Draft23
              , ccServerName = serverName
              , ccALPN       = return $ Just ["h3-24","hq-24"]
              , ccSend       = send
              , ccRecv       = recv
              , ccParams     = exampleParameters
              }
