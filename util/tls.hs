{-# LANGUAGE OverloadedStrings #-}

module Main where

import Network.TLS
import qualified Data.ByteString as B
import System.Environment

import Network.QUIC

main :: IO ()
main = do
    [key, cert] <- getArgs
    (cctx, cparams) <- tlsClientContext "www.mew.org"
    (ch, exts) <- makeClientHello13 cparams cctx
    (sctx, sparams) <- tlsServerContext key cert
    (sh:oth, _, _, _, _) <- makeServerHandshake13 sparams sctx ch
    (handKey, resuming) <- handleServerHello13 cparams cctx sh exts
    makeClientFinished13 cparams cctx (B.concat oth) handKey resuming
