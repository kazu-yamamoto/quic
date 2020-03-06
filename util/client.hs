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
    optDebugLog   :: Bool
  , optQLogDir    :: Maybe FilePath
  , optKeyLogFile :: Maybe FilePath
  , optGroups     :: Maybe String
  , optValidate   :: Bool
  , optHQ         :: Bool
  , optVerNego    :: Bool
  , optResumption :: Bool
  , opt0RTT       :: Bool
  , optQuantum    :: Bool
  , optMigration  :: Maybe Migration
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optDebugLog   = False
  , optQLogDir    = Nothing
  , optKeyLogFile = Nothing
  , optGroups     = Nothing
  , optHQ         = False
  , optValidate   = False
  , optVerNego    = False
  , optResumption = False
  , opt0RTT       = False
  , optQuantum    = False
  , optMigration  = Nothing
  }

usage :: String
usage = "Usage: client [OPTION] addr port"

options :: [OptDescr (Options -> Options)]
options = [
    Option ['d'] ["debug"]
    (NoArg (\o -> o { optDebugLog = True }))
    "print debug info"
  , Option ['q'] ["qlog-dir"]
    (ReqArg (\dir o -> o { optQLogDir = Just dir }) "<dir>")
    "directory to store qlog"
  , Option ['l'] ["key-log-file"]
    (ReqArg (\file o -> o { optKeyLogFile = Just file }) "<file>")
    "a file to store negotiated secrets"
  , Option ['g'] ["groups"]
    (ReqArg (\gs o -> o { optGroups = Just gs }) "<groups>")
    "specify groups"
  , Option ['c'] ["validate"]
    (NoArg (\o -> o { optValidate = True }))
    "validate server's certificate"
  , Option ['r'] ["hq"]
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
  , Option ['M'] ["migration"]
    (NoArg (\o -> o { optMigration = Just SwitchCID }))
    "use a new CID"
  , Option ['B'] ["nat-rebinding"]
    (NoArg (\o -> o { optMigration = Just NATRebiding }))
    "use a new local port"
  , Option ['A'] ["address-mobility"]
    (NoArg (\o -> o { optMigration = Just MigrateTo }))
    "use a new address and a new CID"
  ]

showUsageAndExit :: String -> IO a
showUsageAndExit msg = do
    putStrLn msg
    putStrLn $ usageInfo usage options
    exitFailure

clientOpts :: [String] -> IO (Options, [String])
clientOpts argv =
    case getOpt Permute options argv of
      (o,n,[]  ) -> return (foldl (flip id) defaultOptions o, n)
      (_,_,errs) -> showUsageAndExit $ concat errs

main :: IO ()
main = do
    args <- getArgs
    (Options{..}, ips) <- clientOpts args
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
              , confKeyLog     = getLogger optKeyLogFile
              , confGroups     = getGroups optGroups
              , confCiphers    = [ cipher_TLS13_AES256GCM_SHA384
                                 , cipher_TLS13_AES128GCM_SHA256
                                 , cipher_TLS13_AES128CCM_SHA256
                                 ]
              , confDebugLog   = getStdoutLogger optDebugLog
              , confQLog       = getDirLogger optQLogDir ".qlog"
              }
          }
    putStrLn "------------------------"
    res <- runQUICClient conf $ \conn -> do
        info <- getConnectionInfo conn
        let client = case alpn info of
              Just proto | "hq" `BS.isPrefixOf` proto -> clientHQ cmd
              _                                       -> clientH3 addr
        case optMigration of
          Nothing -> return ()
          Just mtyp -> do
              threadDelay 600000 -- fixme
              res <- migration conn mtyp
              putStrLn $ "Migration by " ++ show mtyp ++ ": " ++ show res
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
