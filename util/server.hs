{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
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
          , scALPN         = Just (\_ -> return "hq-24")
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
              when optDebug $ getConnectionInfo conn >>= print
              void $ forkFinally (server conn) (\_ -> close conn)

server :: Connection -> IO ()
server conn = loop
  where
    loop = do
        bs <- recv conn
        if bs == "" then
            putStrLn "Stream finished"
          else do
            C8.putStr bs
            send conn "<html><body>Hello world!</body></html>\n"
            server conn

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
