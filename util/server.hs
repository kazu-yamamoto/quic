{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import Data.Map (Map)
import qualified Data.Map as Map
import Network.TLS (SessionManager(..), SessionID, SessionData)
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit

import Network.QUIC

import Common

data Options = Options {
    optDebug      :: Bool
  , optRetry      :: Bool
  , optCertFile   :: FilePath
  , optKeyFile    :: FilePath
  , optKeyLogging :: Maybe FilePath
  , optGroups     :: Maybe String
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optDebug      = False
  , optRetry      = False
  , optCertFile   = "servercert.pem"
  , optKeyFile    = "serverkey.pem"
  , optKeyLogging = Nothing
  , optGroups     = Nothing
  }

options :: [OptDescr (Options -> Options)]
options = [
    Option ['d'] ["debug"]
    (NoArg (\o -> o { optDebug = True }))
    "print debug info"
  , Option ['r'] ["retry"]
    (NoArg (\o -> o { optRetry = True }))
    "requre retry"
  , Option ['c'] ["cert"]
    (ReqArg (\fl o -> o { optCertFile = fl }) "FILE")
    "certificate file"
  , Option ['k'] ["key"]
    (ReqArg (\fl o -> o { optKeyFile = fl }) "FILE")
    "key file"
  , Option ['l'] ["key-logging"]
    (ReqArg (\file o -> o { optKeyLogging = Just file }) "Log file")
    "log negotiated secrets"
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

chooseALPN :: [ByteString] -> IO ByteString
chooseALPN protos
  | "hq-24" `elem` protos = return "hq-24"
  | otherwise             = return "h3-24"

main :: IO ()
main = do
    args <- getArgs
    (Options{..}, ips) <- compilerOpts args
    when (length ips /= 2) $ showUsageAndExit "cannot recognize <addr> and <port>\n"
    let [addr,port] = ips
    smgr <- newSessionManager
    let conf = defaultServerConfig {
            scAddresses    = [(read addr, read port)]
          , scKey          = optKeyFile
          , scCert         = optCertFile
          , scALPN         = Just chooseALPN
          , scRequireRetry = optRetry
          , scSessionManager = smgr
          , scEarlyDataSize  = 1024
          , scConfig     = defaultConfig {
                confParameters = exampleParameters
              , confKeyLogging = getLogger optKeyLogging
              , confGroups     = getGroups optGroups
              }
          }
    withQUICServer conf $ \qs -> forever $ do
        econn <- E.try $ accept qs
        case econn of
          Left e
            | Just E.UserInterrupt <- E.fromException e -> E.throwIO e
            | otherwise -> return ()
          Right conn -> do
              info <- getConnectionInfo conn
              when optDebug $ print info
              let server = case alpn info of
                    Just "hq-24" -> serverHQ
                    _            -> serverH3
              void $ forkFinally (server conn) (\_ -> close conn)

serverHQ :: Connection -> IO ()
serverHQ conn = loop
  where
    loop = do
        bs <- recv conn
        if bs == "" then
            putStrLn "Connection finished"
          else do
            C8.putStr bs
            send conn "<html><body>Hello world!</body></html>\n"
            loop

serverH3 :: Connection -> IO ()
serverH3 conn = do
    sendStream conn 3 $ BS.pack [0,4,8,1,80,0,6,128,0,128,0]
    sendStream conn 7 $ BS.pack [2]
    sendStream conn 11 $ BS.pack [3]
    loop
  where
    loop = do
        (sid, bs) <- recvStream conn
        putStrLn $ "SID: " ++ show sid
        if bs == "" then
            putStrLn "Connection finished"
          else do
            print $ BS.unpack bs
            when (sid == 0) $ sendStream conn 0 $ BS.pack [1,27,0,0,219,95,77,143,170,105,210,154,217,98,169,146,74,196,162,11,103,114,217,244,84,3,49,52,55,0,64,147,60,104,116,109,108,62,60,104,101,97,100,62,60,116,105,116,108,101,62,52,48,52,32,78,111,116,32,70,111,117,110,100,60,47,116,105,116,108,101,62,60,47,104,101,97,100,62,60,98,111,100,121,62,60,104,49,62,52,48,52,32,78,111,116,32,70,111,117,110,100,60,47,104,49,62,60,104,114,62,60,97,100,100,114,101,115,115,62,110,103,104,116,116,112,51,47,110,103,116,99,112,50,32,115,101,114,118,101,114,32,97,116,32,112,111,114,116,32,49,51,52,52,51,60,47,97,100,100,114,101,115,115,62,60,47,98,111,100,121,62,60,47,104,116,109,108,62,1,19,0,1,47,6,242,181,83,36,149,137,100,38,194,142,149,141,39,1,48]
            loop

newSessionManager :: IO SessionManager
newSessionManager = sessionManager <$> newIORef Map.empty

sessionManager :: IORef (Map SessionID SessionData) -> SessionManager
sessionManager ref = SessionManager {
    sessionResume = \key -> Map.lookup key <$> readIORef ref
  , sessionResumeOnlyOnce = \key -> Map.lookup key <$> readIORef ref
  , sessionEstablish = \key val -> atomicModifyIORef' ref $ \m ->
      (Map.insert key val m, ())
  , sessionInvalidate = \key -> atomicModifyIORef' ref $ \m ->
      (Map.delete key m, ())
  }
