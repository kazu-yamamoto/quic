{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
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
  , optDebug :: Bool
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optKeyLogging = Nothing
  , optValidate = False
  , optGroups = Nothing
  , optResumption = False
  , opt0RTT = False
  , optDebug = False
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
  , Option ['d'] ["debug"]
    (NoArg (\o -> o { optDebug = True }))
    "print debug info"
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
    let ipslen = length ips
    when (ipslen /= 2 && ipslen /= 3) $
        showUsageAndExit "cannot recognize <addr> and <port>\n"
    let path | ipslen == 3 = "/" ++ (ips !! 2)
             | otherwise   = "/"
        cmd = C8.pack ("GET " ++ path ++ "\r\n")
        addr:port:_ = ips
        conf = defaultClientConfig {
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
        when optDebug $ getConnectionInfo conn >>= print
        client conn cmd `E.finally` close conn
    when (opt0RTT && not (is0RTTPossible res)) $ do
        putStrLn "0-RTT is not allowed"
        exitFailure
    when (optResumption || opt0RTT) $ do
        let rtt0 = opt0RTT && is0RTTPossible res
        let conf'
              | rtt0 = conf {
                    ccResumption = res
                  , ccEarlyData  = Just (0, cmd)
                  }
              | otherwise = conf { ccResumption = res }
        void $ withQUICClient conf' $ \qc -> do
            conn <- connect qc
            when optDebug $ getConnectionInfo conn >>= print
            if rtt0 then do
                putStrLn "------------------------ Response for early data"
                recv conn >>= C8.putStr
                putStrLn "------------------------ Response for early data"
                close conn
              else
                void $ client conn cmd `E.finally` close conn

client :: Connection -> ByteString -> IO ResumptionInfo
client conn cmd = do
    putStrLn "------------------------"
    send conn cmd
    recv conn >>= C8.putStr
    putStrLn "------------------------"
    getResumptionInfo conn
