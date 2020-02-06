{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE StrictData #-}

module Main where

import Control.Concurrent
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Network.TLS.Extra.Cipher
import System.Console.GetOpt
import System.Environment
import System.Exit

import Network.QUIC

import Common
import H3

data Options = Options {
    optDebug      :: Bool
  , optKeyLogging :: Maybe FilePath
  , optGroups     :: Maybe String
  , optValidate   :: Bool
  , optHQ         :: Bool
  , optVerNego    :: Bool
  , optResumption :: Bool
  , opt0RTT       :: Bool
  , optQuantum    :: Bool
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optDebug      = False
  , optKeyLogging = Nothing
  , optGroups     = Nothing
  , optHQ         = False
  , optValidate   = False
  , optVerNego    = False
  , optResumption = False
  , opt0RTT       = False
  , optQuantum    = False
  }

usage :: String
usage = "Usage: client [OPTION] addr port"

options :: [OptDescr (Options -> Options)]
options = [
    Option ['d'] ["debug"]
    (NoArg (\o -> o { optDebug = True }))
    "print debug info"
  , Option ['l'] ["key-logging"]
    (ReqArg (\file o -> o { optKeyLogging = Just file }) "Log file")
    "log negotiated secrets"
  , Option ['g'] ["groups"]
    (ReqArg (\gs o -> o { optGroups = Just gs }) "Groups")
    "specify groups"
  , Option ['c'] ["validate"]
    (NoArg (\o -> o { optValidate = True }))
    "validate server's certificate"
  , Option ['q'] ["hq"]
    (NoArg (\o -> o { optHQ = True }))
    "prefer hq (HTTP/0.9)"
  , Option ['V'] ["vernego"]
    (NoArg (\o -> o { optVerNego = True }))
    "try version negotiation"
  , Option ['R'] ["resumption"]
    (NoArg (\o -> o { optResumption = True }))
    "try session resumption"
  , Option ['Z'] ["0rtt"]
    (NoArg (\o -> o { opt0RTT = True }))
    "try sending early data"
  , Option ['Q'] ["resumption"]
    (NoArg (\o -> o { optQuantum = True }))
    "try sending large Initials"
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
          , ccALPN       = \ver -> let (h3X, hqX) = makeProtos ver
                                       protos
                                         | optHQ     = [hqX,h3X]
                                         | otherwise = [h3X,hqX]
                                   in return $ Just protos
          , ccValidate   = optValidate
          , ccConfig     = defaultConfig {
                confVersions   = if optVerNego then
                                   GreasingVersion : confVersions defaultConfig
                                 else
                                   confVersions defaultConfig
              , confParameters = if optQuantum then
                                   exampleParameters {
                                       greaseParameter = Just (BS.pack (replicate 1200 0))
                                     }
                                 else
                                   exampleParameters
              , confKeyLogging = getLogger optKeyLogging
              , confGroups     = getGroups optGroups
              , confCiphers    = [ cipher_TLS13_AES256GCM_SHA384
                                 , cipher_TLS13_AES128GCM_SHA256
                                 , cipher_TLS13_AES128CCM_SHA256
                                 ]
              }
          }
    putStrLn "------------------------"
    res <- runQUICClient conf $ \conn -> do
        info <- getConnectionInfo conn
        when optDebug $ do
            threadDelay 10000
            print info
        let client = case alpn info of
              Just proto | "hq" `BS.isPrefixOf` proto -> clientHQ cmd
              _                                       -> clientH3 addr
        client conn
    when (optResumption && not (isResumptionPossible res)) $ do
        putStrLn "Resumption is not available"
        exitFailure
    when (opt0RTT && not (is0RTTPossible res)) $ do
        putStrLn "0-RTT is not allowed"
        exitFailure
    threadDelay 100000
    if not optResumption && not opt0RTT then
        exitSuccess
      else do
        let rtt0 = opt0RTT && is0RTTPossible res
        let conf'
              | rtt0 = conf {
                    ccResumption = res
                  , ccEarlyData  = Just (0, cmd) -- fixme
                  }
              | otherwise = conf { ccResumption = res }
        putStrLn "<<<< next connection >>>>"
        putStrLn "------------------------"
        void $ runQUICClient conf' $ \conn -> do
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
                exitSuccess
              else do
                let client = case alpn info of
                      Just proto | "hq" `BS.isPrefixOf` proto -> clientHQ cmd
                      _                                       -> clientH3 addr
                void $ client conn
                exitSuccess

clientHQ :: ByteString -> Connection -> IO ResumptionInfo
clientHQ cmd conn = do
    putStrLn "------------------------"
    send conn cmd
    shutdown conn
    (sid, bs) <- recvStream conn
    when (sid /= 0) $ putStrLn $ "SID: " ++ show sid
    C8.putStr bs
    putStrLn "\n------------------------"
    threadDelay 300000
    getResumptionInfo conn

clientH3 :: String -> Connection -> IO ResumptionInfo
clientH3 authority conn = do
    putStrLn "------------------------"
    hdrblk <- taglen 1 <$> qpackClient authority
    sendStream conn  2 False $ BS.pack [0,4,8,1,80,0,6,128,0,128,0]
    sendStream conn  6 False $ BS.pack [2]
    sendStream conn 10 False $ BS.pack [3]
    sendStream conn  0 True hdrblk
    loop
    putStrLn "------------------------"
    getResumptionInfo conn
  where
    loop = do
        (sid, bs) <- recvStream conn
        putStrLn $ "SID: " ++ show sid
        if bs == "" then
            putStrLn "Connection finished"
          else do
            print $ BS.unpack bs
            loop
