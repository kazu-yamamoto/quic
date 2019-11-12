{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Monad (void)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as C8
import Network.QUIC
import Network.Run.UDP
import Network.Socket hiding (Stream)
import qualified Network.Socket.ByteString as NSB
import System.Environment (getArgs)

main :: IO ()
main = do
    [port,cert,key] <- getArgs
    runUDPServerFork ["127.0.0.1","::1"] port $ \s bs0 -> quicServer s bs0 cert key

quicServer :: Socket -> ByteString -> FilePath -> FilePath -> IO ()
quicServer s bs0 cert key = do
    let conf = defaultServerConfig {
            scVersion    = Draft23
          , scKey        = key
          , scCert       = cert
          , scSend       = \bs -> void $ NSB.send s bs
          , scRecv       = NSB.recv s 2048
          , scParams     = exampleParameters
          , scClientIni  = bs0
          , scALPN       = Just (\_ -> return "hq-23")
          }
    mctx <- serverContext conf
    case mctx of
      Nothing -> putStrLn "Client Initial is broken"
      Just ctx -> do
          handshake ctx
          loop ctx
  where
    loop ctx = do
        bs <- recvData ctx
        if bs == "" then do
            putStrLn "Stream finished"
            bye ctx
          else do
            C8.putStr bs
            sendData ctx "<html><body>Hello world!</body></html>"
            loop ctx
