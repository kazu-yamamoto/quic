{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as C8
import System.Environment

import Network.QUIC

main :: IO ()
main = do
    [serverName,portName] <- getArgs
    let conf = defaultClientConfig {
            ccServerName = serverName
          , ccPortName   = portName
          , ccALPN       = return $ Just ["h3-24","hq-24"]
          , ccParameters = exampleParameters
          }
    withQUICClient conf $ \qc -> do
        conn <- connect qc
        client conn `E.finally` close conn

client :: Connection -> IO ()
client conn = do
    sendData conn "GET /index.html\r\n"
    recvData conn >>= C8.putStr
