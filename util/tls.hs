{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Concurrent
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Network.TLS
import System.Environment

import Network.QUIC

type Channel = MVar [ByteString]

main :: IO ()
main = do
    mvar <- newEmptyMVar
    _ <- forkIO $ server mvar
    client mvar

server :: Channel -> IO ()
server mvar = do
    [key, cert] <- getArgs
    [chRaw] <- takeMVar mvar
    (sctx, sparams) <- tlsServerContext key cert
    --------------------
    putStrLn "---- SERVER ----"
    (shRaws, _, _, _, _) <- makeServerHandshake13 sparams sctx chRaw
    putMVar mvar shRaws

client :: Channel -> IO ()
client mvar = do
    let conf = defaultClientConfig {
            ccVersion    = Draft22
          , ccServerName = "www.mew.org"
          }
    (cctx, cparams) <- tlsClientContext (ccServerName conf) (ccCiphers conf) (ccALPN conf)
    --------------------
    putStrLn "---- CLIENT ---- CH"
    (ch, chRaw) <- makeClientHello13 cparams cctx []
    --------------------
    putMVar mvar [chRaw]
    shRaw:sRaws <- takeMVar mvar
    --------------------
    putStrLn "---- CLIENT ---- CF"
    (_cipher, handSecret, resuming) <- handleServerHello13 cparams cctx ch shRaw
    putStr "    Cipher = "
    print _cipher
    _ <- makeClientFinished13 cparams cctx (BS.concat sRaws) handSecret resuming
    return ()
