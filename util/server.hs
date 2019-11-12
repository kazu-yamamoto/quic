{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Control.Exception as E
import Control.Monad (void)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as C8
import Network.Run.UDP
import Network.Socket hiding (Stream)
import qualified Network.Socket.ByteString as NSB
import System.Environment (getArgs)

import Network.QUIC

main :: IO ()
main = do
    [port,cert,key] <- getArgs
    runUDPServerFork ["127.0.0.1","::1"] port $ \s bs0 -> quicServer s bs0 cert key

quicServer :: Socket -> ByteString -> FilePath -> FilePath -> IO ()
quicServer s bs0 cert key =
    E.bracket (handshake conf) bye server
  where
    server ctx = do
        bs <- recvData ctx
        if bs == "" then
            putStrLn "Stream finished"
          else do
            C8.putStr bs
            sendData ctx "<html><body>Hello world!</body></html>"
            server ctx
    conf = defaultServerConfig {
            scVersion    = Draft23
          , scKey        = key
          , scCert       = cert
          , scSend       = \bs -> void $ NSB.send s bs
          , scRecv       = NSB.recv s 2048
          , scParams     = exampleParameters
          , scClientIni  = bs0
          , scALPN       = Just (\_ -> return "hq-23")
          }
