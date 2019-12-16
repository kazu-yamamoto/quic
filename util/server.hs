{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent
import Control.Monad
import qualified Data.ByteString.Char8 as C8
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit

import Network.QUIC

import Common

data Options = Options {
    optRetry      :: Bool
  , optKeyLogging :: Bool
  , optKeyFile    :: FilePath
  , optCertFile   :: FilePath
  , optGroups     :: Maybe String
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optRetry      = False
  , optKeyLogging = False
  , optKeyFile    = "serverkey.pem"
  , optCertFile   = "servercert.pem"
  , optGroups = Nothing
  }

options :: [OptDescr (Options -> Options)]
options = [
    Option ['r'] ["retry"]
    (NoArg (\o -> o { optRetry = True }))
    "requre retry"
  , Option ['l'] ["key-logging"]
    (NoArg (\o -> o { optKeyLogging = True }))
    "print negotiated secrets"
  , Option ['k'] ["key"]
    (ReqArg (\fl o -> o { optKeyFile = fl }) "FILE")
    "key file"
  , Option ['c'] ["cert"]
    (ReqArg (\fl o -> o { optCertFile = fl }) "FILE")
    "certificate file"
  , Option ['g'] ["groups"]
    (ReqArg (\gs o -> o { optGroups = Just gs }) "Groups")
    "specify groups"
  ]

usage :: String
usage = "Usage: server [OPTION] addr port"

showUsageAndExit :: String -> IO a
showUsageAndExit msg = do
    putStrLn msg
    putStrLn $ usageInfo usage options
    exitFailure

compilerOpts :: [String] -> IO (Options, [String])
compilerOpts argv =
    case getOpt Permute options argv of
      (o,n,[]  ) -> return (foldl (flip id) defaultOptions o, n)
      (_,_,errs) -> showUsageAndExit $ concat errs

main :: IO ()
main = do
    args <- getArgs
    (Options{..}, ips) <- compilerOpts args
    when (length ips /= 2) $ showUsageAndExit "cannot recognize <addr> and <port>\n"
    let [addr,port] = ips
    let conf = defaultServerConfig {
            scAddresses    = [(read addr, read port)]
          , scKey          = optKeyFile
          , scCert         = optCertFile
          , scALPN         = Just (\_ -> return "hq-24")
          , scRequireRetry = optRetry
          , scConfig     = defaultConfig {
                confParameters = exampleParameters
              , confKeyLogging = optKeyLogging
              , confGroups     = getGroups optGroups
              }
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
            sendData conn "<html><body>Hello world!</body></html>\n"
            server conn
