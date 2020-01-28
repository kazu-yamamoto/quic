{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE StrictData #-}

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
import H3

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
                confParameters = defaultParameters {
                      maxStreamDataBidiLocal  =  262144
                    , maxStreamDataBidiRemote =  262144
                    , maxStreamDataUni        =  262144
                    , maxData                 = 1048576
                    , maxStreamsBidi          =     100
                    , maxStreamsUni           =       3
                    , idleTimeout             =   30000
                    , activeConnectionIdLimit =       7
                    }
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
serverHQ conn = do
    bs <- recv conn
    C8.putStr bs
    send conn html
    shutdown conn
    putStrLn "Connection finished"

serverH3 :: Connection -> IO ()
serverH3 conn = do
    sendStream conn  3 False $ BS.pack [0,4,8,1,80,0,6,128,0,128,0]
    sendStream conn  7 False $ BS.pack [2]
    sendStream conn 11 False $ BS.pack [3]
    hdrblock <- taglen 1 <$> qpackServer
    let bdyblock = taglen 0 html
        hdrbdy = BS.concat [hdrblock,bdyblock]
    loop hdrbdy
  where
    loop hdrbdy = do
        (sid, bs) <- recvStream conn
        putStr $ "SID: " ++ show sid ++ " "
        if bs == "" then do
            putStr "\n"
            loop hdrbdy
          else do
            print $ BS.unpack bs
            when ((sid `mod` 4) == 0) $ sendStream conn sid True hdrbdy
            loop hdrbdy

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
