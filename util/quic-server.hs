{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Main where

import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.List as L
import Network.TLS (Credentials (..), credentialLoadX509)
import qualified Network.TLS.SessionManager as SM
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit
import System.IO

import Common
import Network.QUIC
import Network.QUIC.Internal
import Network.QUIC.Server
import ServerX

data Options = Options
    { optDebugLogDir :: Maybe FilePath
    , optQLogDir :: Maybe FilePath
    , optKeyLogFile :: Maybe FilePath
    , optGroups :: Maybe String
    , optTimeout :: Maybe Int
    , optCertFile :: FilePath
    , optKeyFile :: FilePath
    , optRetry :: Bool
    }
    deriving (Show)

defaultOptions :: Options
defaultOptions =
    Options
        { optDebugLogDir = Nothing
        , optQLogDir = Nothing
        , optKeyLogFile = Nothing
        , optGroups = Nothing
        , optTimeout = Nothing
        , optCertFile = "servercert.pem"
        , optKeyFile = "serverkey.pem"
        , optRetry = False
        }

options :: [OptDescr (Options -> Options)]
options =
    [ Option
        ['d']
        ["debug-log-dir"]
        (ReqArg (\dir o -> o{optDebugLogDir = Just dir}) "<dir>")
        "directory to store a debug file"
    , Option
        ['q']
        ["qlog-dir"]
        (ReqArg (\dir o -> o{optQLogDir = Just dir}) "<dir>")
        "directory to store qlog"
    , Option
        ['l']
        ["key-log-file"]
        (ReqArg (\file o -> o{optKeyLogFile = Just file}) "<file>")
        "a file to store negotiated secrets"
    , Option
        ['g']
        ["groups"]
        (ReqArg (\gs o -> o{optGroups = Just gs}) "<groups>")
        "groups for key exchange"
    , Option
        ['c']
        ["cert"]
        (ReqArg (\fl o -> o{optCertFile = fl}) "<file>")
        "certificate file"
    , Option
        ['k']
        ["key"]
        (ReqArg (\fl o -> o{optKeyFile = fl}) "<file>")
        "key file"
    , Option
        ['S']
        ["retry"]
        (NoArg (\o -> o{optRetry = True}))
        "require stateless retry"
    , Option
        ['o']
        ["timeout"]
        (ReqArg (\tim o -> o{optTimeout = Just (read tim)}) "<timeout>")
        "RX timeout in seconds"
    ]

usage :: String
usage = "Usage: server [OPTION] addr [addrs] port"

showUsageAndExit :: String -> IO a
showUsageAndExit msg = do
    putStrLn msg
    putStrLn $ usageInfo usage options
    exitFailure

serverOpts :: [String] -> IO (Options, [String])
serverOpts argv =
    case getOpt Permute options argv of
        (o, n, []) -> return (foldl (flip id) defaultOptions o, n)
        (_, _, errs) -> showUsageAndExit $ concat errs

chooseALPN :: Version -> [ByteString] -> IO ByteString
chooseALPN _ protos
    | "perf" `elem` protos = return "perf"
chooseALPN ver protos = return $ case mh3idx of
    Nothing -> case mhqidx of
        Nothing -> ""
        Just _ -> hqX
    Just h3idx -> case mhqidx of
        Nothing -> h3X
        Just hqidx -> if h3idx < hqidx then h3X else hqX
  where
    (h3X, hqX) = makeProtos ver
    mh3idx = h3X `L.elemIndex` protos
    mhqidx = hqX `L.elemIndex` protos

main :: IO ()
main = do
    hSetBuffering stdout NoBuffering
    args <- getArgs
    (Options{..}, ips) <- serverOpts args
    when (length ips < 2) $ showUsageAndExit "cannot recognize <addr> and <port>\n"
    let port = read (last ips)
        addrs = read <$> init ips
        aps = (,port) <$> addrs
    smgr <- SM.newSessionManager SM.defaultConfig
    Right cred@(!_cc, !_priv) <- credentialLoadX509 optCertFile optKeyFile
    let sc0 = defaultServerConfig
        sc =
            sc0
                { scAddresses = aps
                , scALPN = Just chooseALPN
                , scRequireRetry = optRetry
                , scSessionManager = smgr
                , scUse0RTT = True
                , scDebugLog = optDebugLogDir
                , scKeyLog = getLogger optKeyLogFile
                , scGroups = getGroups (scGroups sc0) optGroups
                , scQLog = optQLogDir
                , scCredentials = Credentials [cred]
                }
    run sc $ \conn -> do
        case optTimeout of
            Just t -> setMinIdleTimeout conn $ Microseconds $ t * 1000000
            Nothing -> return ()
        info <- getConnectionInfo conn
        let server = case alpn info of
                Just proto
                    | "perf" == proto -> serverPF
                    | "hq" `BS.isPrefixOf` proto -> serverHQ
                _ -> serverH3
        server conn
