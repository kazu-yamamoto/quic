{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent
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
    optDebug      :: Bool
  , opt0RTT       :: Bool
  , optResumption :: Bool
  , optValidate   :: Bool
  , optKeyLogging :: Maybe FilePath
  , optGroups     :: Maybe String
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optDebug      = False
  , opt0RTT       = False
  , optResumption = False
  , optValidate   = False
  , optKeyLogging = Nothing
  , optGroups     = Nothing
  }

usage :: String
usage = "Usage: client [OPTION] addr port"

options :: [OptDescr (Options -> Options)]
options = [
    Option ['d'] ["debug"]
    (NoArg (\o -> o { optDebug = True }))
    "print debug info"
  , Option ['z'] ["rtt0"]
    (NoArg (\o -> o { opt0RTT = True }))
    "resume the previous session and send early data"
  , Option ['r'] ["resumption"]
    (NoArg (\o -> o { optResumption = True }))
    "resume the previous session"
  , Option ['V'] ["validate"]
    (NoArg (\o -> o { optValidate = True }))
    "validate server's certificate"
  , Option ['l'] ["key-logging"]
    (ReqArg (\file o -> o { optKeyLogging = Just file }) "Log file")
    "log negotiated secrets"
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
          , ccALPN       = return $ Just ["hq-24","h3-24"]
          , ccValidate   = optValidate
          , ccConfig     = defaultConfig {
                confParameters = exampleParameters
              , confKeyLogging = getLogger optKeyLogging
              , confGroups     = getGroups optGroups
              }
          }
    putStrLn "------------------------"
    res <- withQUICClient conf $ \qc -> do
        conn <- connect qc
        when optDebug $ getConnectionInfo conn >>= print
        client conn cmd `E.finally` close conn
    when (optResumption && not (isResumptionPossible res)) $ do
        putStrLn "Resumption is not available"
        exitFailure
    when (opt0RTT && not (is0RTTPossible res)) $ do
        putStrLn "0-RTT is not allowed"
        exitFailure
    threadDelay 100000
    when (optResumption || opt0RTT) $ do
        let rtt0 = opt0RTT && is0RTTPossible res
        let conf'
              | rtt0 = conf {
                    ccResumption = res
                  , ccEarlyData  = Just (0, cmd)
                  }
              | otherwise = conf { ccResumption = res }
        putStrLn "<<<< next connection >>>>"
        putStrLn "------------------------"
        void $ withQUICClient conf' $ \qc -> do
            conn <- connect qc
            when optDebug $ getConnectionInfo conn >>= print
            if rtt0 then do
                putStrLn "------------------------ Response for early data"
                (sid, bs) <- recv' conn
                when (sid /= 0) $ putStrLn $ "SID: " ++ show sid
                C8.putStr bs
                putStrLn "------------------------ Response for early data"
                close conn
              else
                void $ client conn cmd `E.finally` close conn

client :: Connection -> ByteString -> IO ResumptionInfo
client conn cmd = do
    putStrLn "------------------------"
    send conn cmd
    (sid, bs) <- recv' conn
    when (sid /= 0) $ putStrLn $ "SID: " ++ show sid
    C8.putStr bs
    putStrLn "------------------------"
    threadDelay 300000
    getResumptionInfo conn
