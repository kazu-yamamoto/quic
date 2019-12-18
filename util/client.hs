{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Control.Exception as E
import Control.Monad
import qualified Data.ByteString.Char8 as C8
import System.Console.GetOpt
import System.Environment
import System.Exit

import Network.QUIC

import Common

data Options = Options {
    optKeyLogging :: Bool
  , optValidate :: Bool
  , optGroups :: Maybe String
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optKeyLogging = False
  , optValidate = False
  , optGroups = Nothing
  }

usage :: String
usage = "Usage: client [OPTION] addr port"

options :: [OptDescr (Options -> Options)]
options = [
    Option ['l'] ["key-logging"]
    (NoArg (\o -> o { optKeyLogging = True }))
    "print negotiated secrets"
  , Option ['V'] ["validate"]
    (NoArg (\o -> o { optValidate = True }))
    "validate server's certificate"
  , Option ['g'] ["groups"]
    (ReqArg (\gs o -> o { optGroups = Just gs }) "Groups")
    "specify groups"
  ]

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
    let conf = defaultClientConfig {
            ccServerName = addr
          , ccPortName   = port
          , ccALPN       = return $ Just ["h3-24","hq-24"]
          , ccValidate   = optValidate
          , ccConfig     = defaultConfig {
                confParameters = exampleParameters
              , confKeyLogging = optKeyLogging
              , confGroups     = getGroups optGroups
              }
          }
    res <- withQUICClient conf $ \qc -> do
        conn <- connect qc
        client conn `E.finally` close conn
    void $ withQUICClient conf { ccResumption = res } $ \qc -> do
        conn <- connect qc
        client conn `E.finally` close conn

client :: Connection -> IO ResumptionInfo
client conn = do
    sendData conn "GET /index.html\r\n"
    recvData conn >>= C8.putStr
    getResumptionInfo conn
