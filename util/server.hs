{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE TupleSections #-}

module Main where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.List as L
import qualified Network.TLS.SessionManager as SM
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit
import System.IO
import System.Timeout

import Network.QUIC

import Common
import H3

data Options = Options {
    optDebug      :: Bool
  , optKeyLogging :: Maybe FilePath
  , optGroups     :: Maybe String
  , optCertFile   :: FilePath
  , optKeyFile    :: FilePath
  , optRetry      :: Bool
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optDebug      = False
  , optKeyLogging = Nothing
  , optGroups     = Nothing
  , optCertFile   = "servercert.pem"
  , optKeyFile    = "serverkey.pem"
  , optRetry      = False
  }

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
  , Option ['c'] ["cert"]
    (ReqArg (\fl o -> o { optCertFile = fl }) "FILE")
    "certificate file"
  , Option ['k'] ["key"]
    (ReqArg (\fl o -> o { optKeyFile = fl }) "FILE")
    "key file"
  , Option ['S'] ["retry"]
    (NoArg (\o -> o { optRetry = True }))
    "requre statelsss retry"
  ]

usage :: String
usage = "Usage: server [OPTION] addr [addrs] port"

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

chooseALPN :: Version -> [ByteString] -> IO ByteString
chooseALPN ver protos = return $ case mh3idx of
    Nothing    -> case mhqidx of
      Nothing    -> ""
      Just _     -> hqX
    Just h3idx ->  case mhqidx of
      Nothing    -> h3X
      Just hqidx -> if h3idx < hqidx then h3X else hqX
  where
    (h3X, hqX) = makeProtos ver
    mh3idx = h3X `L.elemIndex` protos
    mhqidx = hqX `L.elemIndex` protos

main :: IO ()
main = do
    hSetBuffering stdout NoBuffering
    args <- getArgs
    (Options{..}, ips) <- compilerOpts args
    when (length ips < 2) $ showUsageAndExit "cannot recognize <addr> and <port>\n"
    let port = read (last ips)
        addrs = read <$> init ips
        aps = (,port) <$> addrs
    smgr <- SM.newSessionManager SM.defaultConfig
    let conf = defaultServerConfig {
            scAddresses    = aps
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
    E.handle (\(E.SomeException e) -> print e) $ withQUICServer conf $ \qs -> forever $ do
        econn <- E.try $ accept qs
        case econn of
          Left e
            | Just E.UserInterrupt <- E.fromException e -> E.throwIO e
            | otherwise -> return ()
          Right conn -> do
              info <- getConnectionInfo conn
              when optDebug $ print info
              let server = case alpn info of
                    Just proto | "hq" `BS.isPrefixOf` proto -> serverHQ
                    _                                       -> serverH3
              void $ forkFinally (server conn) (\_ -> close conn)

onE :: IO b -> IO a -> IO a
h `onE` b = b `E.onException` h

serverHQ :: Connection -> IO ()
serverHQ conn = putStrLn "Connection terminated" `onE` do
    mbs <- timeout 5000000 $ recv conn
    case mbs of
      Nothing -> putStrLn "Connection timeout"
      Just bs -> do
          C8.putStr bs
          send conn html
          shutdown conn
          putStrLn "Connection finished"

serverH3 :: Connection -> IO ()
serverH3 conn = putStrLn "Connection terminated" `onE` do
    sendStream conn  3 False $ BS.pack [0,4,8,1,80,0,6,128,0,128,0]
    sendStream conn  7 False $ BS.pack [2]
    sendStream conn 11 False $ BS.pack [3]
    hdrblock <- taglen 1 <$> qpackServer
    let bdyblock = taglen 0 html
        hdrbdy = BS.concat [hdrblock,bdyblock]
    loop hdrbdy
  where
    loop hdrbdy = do
        mx <- timeout 5000000 $ recvStream conn
        case mx of
          Nothing -> putStrLn "Connection timeout"
          Just (sid, bs) -> do
              putStr $ "SID: " ++ show sid ++ " "
              print $ BS.unpack bs
              when ((sid `mod` 4) == 0) $ sendStream conn sid True hdrbdy
              loop hdrbdy
