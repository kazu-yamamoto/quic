{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Concurrent
import Control.Monad (void, forever)
import qualified Data.ByteString.Char8 as C8
import System.Environment (getArgs)

import Network.QUIC

main :: IO ()
main = do
    [port,cert,key] <- getArgs
    let conf = defaultServerConfig {
            scAddresses    = [("127.0.0.1", read port)]
          , scKey          = key
          , scCert         = cert
          , scParameters   = exampleParameters
          , scALPN         = Just (\_ -> return "hq-24")
          , scRequireRetry = False
          }
    withQUICServer conf $ \qs -> forever $ do
        conn <- accept qs
        void $ forkFinally (server conn) (\_ -> close conn)

server :: Connection -> IO ()
server conn = loop
  where
    loop = do
        bs <- recvData conn
        if bs == "" then
            putStrLn "Stream finished"
          else do
            C8.putStr bs
            sendData conn "<html><body>Hello world!</body></html>"
            server conn
