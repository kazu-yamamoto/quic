{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
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
        info <- getConnectionInfo conn
        when optDebug $ do
            threadDelay 10000
            print info
        let client = case alpn info of
              Just "hq-24" -> clientHQ cmd
              _            -> clientH3
        client conn `E.finally` close conn
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
                  , ccEarlyData  = Just (0, cmd) -- fixme
                  }
              | otherwise = conf { ccResumption = res }
        putStrLn "<<<< next connection >>>>"
        putStrLn "------------------------"
        void $ withQUICClient conf' $ \qc -> do
            conn <- connect qc
            info <- getConnectionInfo conn
            when optDebug $ do
                threadDelay 10000
                print info
            if rtt0 then do
                putStrLn "------------------------ Response for early data"
                (sid, bs) <- recvStream conn
                putStrLn $ "SID: " ++ show sid
                C8.putStrLn bs
                putStrLn "------------------------ Response for early data"
                close conn
              else do
                let client = case alpn info of
                      Just "hq-24" -> clientHQ cmd
                      _            -> clientH3
                void $ client conn `E.finally` close conn

clientH3 :: Connection -> IO ResumptionInfo
clientH3 conn = do
    putStrLn "------------------------"
    sendStream conn  2 $ BS.pack [0,4,8,1,80,0,6,128,0,128,0]
    sendStream conn  6 $ BS.pack [2]
    sendStream conn 10 $ BS.pack [3]
    sendStream conn  0 $ BS.pack [1,31,0,0,209,214,80,134,160,228,29,19,157,9,193,95,80,143,170,105,210,154,217,98,169,146,74,196,161,40,49,106,79]
    shutdownStream conn 0
    loop
    putStrLn "------------------------"
    getResumptionInfo conn
  where
    loop = do
        (sid, bs) <- recvStream conn
        if bs == "" then
            putStrLn "Connection finished"
          else do
            putStrLn $ "SID: " ++ show sid
            print $ BS.unpack bs
            loop

clientHQ :: ByteString -> Connection -> IO ResumptionInfo
clientHQ cmd conn = do
    putStrLn "------------------------"
    send conn cmd
    shutdown conn
    (sid, bs) <- recvStream conn
    when (sid /= 0) $ putStrLn $ "SID: " ++ show sid
    C8.putStr bs
    putStrLn "------------------------"
    threadDelay 300000
    getResumptionInfo conn
