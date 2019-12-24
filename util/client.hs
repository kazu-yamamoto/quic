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
    optKeyLogging :: Maybe FilePath
  , optValidate :: Bool
  , optGroups :: Maybe String
  , optResumption :: Bool
  , opt0RTT :: Bool
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optKeyLogging = Nothing
  , optValidate = False
  , optGroups = Nothing
  , optResumption = False
  , opt0RTT = False
  }

usage :: String
usage = "Usage: client [OPTION] addr port"

options :: [OptDescr (Options -> Options)]
options = [
    Option ['l'] ["key-logging"]
    (ReqArg (\file o -> o { optKeyLogging = Just file }) "Log file")
    "log negotiated secrets"
  , Option ['V'] ["validate"]
    (NoArg (\o -> o { optValidate = True }))
    "validate server's certificate"
  , Option ['g'] ["groups"]
    (ReqArg (\gs o -> o { optGroups = Just gs }) "Groups")
    "specify groups"
  , Option ['r'] ["resumption"]
    (NoArg (\o -> o { optResumption = True }))
    "resume the previous session"
  , Option ['z'] ["rtt0"]
    (NoArg (\o -> o { opt0RTT = True }))
    "resume the previous session and send early data"
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
              , confKeyLogging = getLogger optKeyLogging
              , confGroups     = getGroups optGroups
              }
          }
    res <- withQUICClient conf $ \qc -> do
        conn <- connect qc
        client conn `E.finally` close conn
    when (opt0RTT && not (is0RTTPossible res)) $ do
        putStrLn "0-RTT is not allowed"
        exitFailure
    when (optResumption || opt0RTT) $ do
        let rtt0 = opt0RTT && is0RTTPossible res
        let conf'
              | rtt0 = conf {
                    ccResumption = res
                  , ccEarlyData  = Just (0, "GET /\r\n")
                  }
              | otherwise = conf { ccResumption = res }
        void $ withQUICClient conf' $ \qc -> do
            conn <- connect qc
            if rtt0 then do
                putStrLn "------------------------ Response for early data"
                recv conn >>= C8.putStr
                putStrLn "------------------------ Response for early data"
                close conn
              else
                void $ client conn `E.finally` close conn

client :: Connection -> IO ResumptionInfo
client conn = do
    putStrLn "------------------------"
    send conn "GET /\r\n"
    recv conn >>= C8.putStr
    putStrLn "------------------------"
    getResumptionInfo conn
