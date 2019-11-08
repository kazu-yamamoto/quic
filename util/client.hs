{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad
import qualified Data.ByteString.Char8 as C8
import Network.QUIC
import Network.Run.UDP
import Network.Socket hiding (Stream)
import Network.Socket.ByteString
import System.Environment

main :: IO ()
main = do
    [serverName,port] <- getArgs
    runUDPClient serverName port $ quicClient serverName

quicClient :: String -> Socket -> SockAddr -> IO ()
quicClient serverName s peerAddr = do
    let conf = defaultClientConfig {
            ccVersion    = Draft23
          , ccServerName = serverName
--          , ccALPN       = return $ Just ["hq-23"]
          , ccALPN       = return $ Just ["h3-23"]
          , ccSend       = \bs -> void $ sendTo s bs peerAddr
          , ccRecv       = fst <$> recvFrom s 2048
          , ccParams     = exampleParameters
          }
    ctx <- clientContext conf
    handshake ctx
    sendData ctx "GET /index.html\r\n"
    recvData ctx >>= C8.putStrLn
