{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import Network.QUIC
import Network.Run.UDP
import Network.Socket hiding (Stream)
import qualified Network.Socket.ByteString as NSB
import System.Environment

main :: IO ()
main = do
    [serverName,port] <- getArgs
    runUDPClient serverName port $ quicClient serverName

quicClient :: String -> Socket -> SockAddr -> IO ()
quicClient serverName s peerAddr = do
    ref <- newIORef peerAddr
    let recv = do
            (bs, peer) <- NSB.recvFrom s 2048
            writeIORef ref peer
            return bs
        send bs = do
            peer <- readIORef ref
            void $ NSB.sendTo s bs peer
    let conf = defaultClientConfig {
            ccVersion    = Draft23
          , ccServerName = serverName
--          , ccALPN       = return $ Just ["hq-23"]
          , ccALPN       = return $ Just ["h3-23"]
          , ccSend       = send
          , ccRecv       = recv
          , ccParams     = exampleParameters
          }
    ctx <- clientContext conf
    handshake ctx
    sendData ctx "GET /index.html\r\n"
    recvData ctx >>= C8.putStrLn
