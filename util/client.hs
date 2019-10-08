{-# LANGUAGE OverloadedStrings #-}

module Main where

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
          , ccALPN       = return $ Just ["h3-23"]
          , ccSend       = \bs -> sendTo s bs peerAddr >> return ()
          , ccRecv       = fst <$> recvFrom s 2048
          }
    ctx <- clientContext conf
    handshake ctx
