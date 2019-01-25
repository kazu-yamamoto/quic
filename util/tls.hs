{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.Default.Class
import Network.TLS
import Network.TLS.Extra.Cipher
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Base16
import System.Environment

main :: IO ()
main = do
    [key, cert] <- getArgs
    let backend = Backend (return ()) (return ()) (\_ -> return ()) (\_ -> return "")
        supported = def {
            supportedVersions = [TLS13]
          , supportedCiphers = ciphersuite_strong
          }
    Right cred <- credentialLoadX509 cert key
    let sshared = def {
            sharedCredentials = Credentials [cred]
          }
    let cshared = def {
           sharedValidationCache = ValidationCache (\_ _ _ -> return ValidationCachePass) (\_ _ _ -> return ())
          }
        debug = def {
            debugKeyLogger = putStrLn
          }
    let cparams = (defaultParamsClient "www.mew.org" "") {
            clientSupported = supported
          , clientDebug = debug
          , clientShared = cshared
          }
        sparams = def {
            serverSupported = supported
          , serverDebug = debug
          , serverShared = sshared
          }
    cctx <- contextNew backend cparams
    (ch, exts) <- makeClientHello13 cparams cctx
    sctx <- contextNew backend sparams
    (sh:oth, _, _, _, _) <- makeServerHandshake13 sparams sctx ch
    (handKey, resuming) <- handleServerHello13 cparams cctx sh exts
    makeClientFinished13 cparams cctx (B.concat oth) handKey resuming
