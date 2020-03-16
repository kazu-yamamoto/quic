{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE TupleSections #-}

module Main where

import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.List as L
import Network.TLS.Extra.Cipher
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
    optDebugLogDir :: Maybe FilePath
  , optQLogDir     :: Maybe FilePath
  , optKeyLogFile  :: Maybe FilePath
  , optGroups      :: Maybe String
  , optCertFile    :: FilePath
  , optKeyFile     :: FilePath
  , optRetry       :: Bool
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optDebugLogDir = Nothing
  , optQLogDir     = Nothing
  , optKeyLogFile  = Nothing
  , optGroups      = Nothing
  , optCertFile    = "servercert.pem"
  , optKeyFile     = "serverkey.pem"
  , optRetry       = False
  }

options :: [OptDescr (Options -> Options)]
options = [
    Option ['d'] ["debug-log-dir"]
    (ReqArg (\dir o -> o { optDebugLogDir = Just dir }) "<dir>")
    "directory to store a debug file"
  , Option ['q'] ["qlog-dir"]
    (ReqArg (\dir o -> o { optQLogDir = Just dir }) "<dir>")
    "directory to store qlog"
  , Option ['l'] ["key-log-file"]
    (ReqArg (\file o -> o { optKeyLogFile = Just file }) "<file>")
    "a file to store negotiated secrets"
  , Option ['g'] ["groups"]
    (ReqArg (\gs o -> o { optGroups = Just gs }) "<groups>")
    "groups for key exchange"
  , Option ['c'] ["cert"]
    (ReqArg (\fl o -> o { optCertFile = fl }) "<file>")
    "certificate file"
  , Option ['k'] ["key"]
    (ReqArg (\fl o -> o { optKeyFile = fl }) "<file>")
    "key file"
  , Option ['S'] ["retry"]
    (NoArg (\o -> o { optRetry = True }))
    "require stateless retry"
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
    (Options{..}, ips) <- serverOpts args
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
                    }
              , confKeyLog     = getLogger optKeyLogFile
              , confGroups     = getGroups optGroups
              , confCiphers    = [ cipher_TLS13_AES256GCM_SHA384
                                 , cipher_TLS13_AES128GCM_SHA256
                                 , cipher_TLS13_AES128CCM_SHA256
                                 ]
              , confDebugLog   = getDirLogger optDebugLogDir ".txt"
              , confQLog       = getDirLogger optQLogDir ".qlog"
              }
          }
    runQUICServer conf $ \conn -> do
        info <- getConnectionInfo conn
        let server = case alpn info of
              Just proto | "hq" `BS.isPrefixOf` proto -> serverHQ
              _                                       -> serverH3
        server conn

onE :: IO b -> IO a -> IO a
h `onE` b = b `E.onException` h

serverHQ :: Connection -> IO ()
serverHQ conn = connDebugLog conn "Connection terminated" `onE` loop
  where
    loop = do
        mbs <- timeout 5000000 $ recv conn
        case mbs of
          Nothing -> connDebugLog conn "Connection timeout"
          Just "" -> do
              send conn html
              shutdown conn
              connDebugLog conn "Connection finished"
          Just bs -> do
              connDebugLog conn $ C8.unpack bs
              loop

serverH3 :: Connection -> IO ()
serverH3 conn = connDebugLog conn "Connection terminated" `onE` do
    -- 0: control, 4 settings
    sendStream conn  3 False $ BS.pack [0,4,8,1,80,0,6,128,0,128,0]
    -- 2: from encoder to decoder
    sendStream conn  7 False $ BS.pack [2]
    -- 3: from decoder to encoder
    sendStream conn 11 False $ BS.pack [3]
    hdrblock <- taglen 1 <$> qpackServer
    let bdyblock = taglen 0 html
        hdrbdy = BS.concat [hdrblock,bdyblock]
    loop hdrbdy
  where
    loop hdrbdy = do
        mx <- timeout 5000000 $ recvStream conn
        case mx of
          Nothing -> connDebugLog conn "Connection timeout"
          Just (sid, bs) -> do
              connDebugLog conn ("SID: " ++ show sid ++ " " ++ show (BS.unpack bs))
              when ((sid `mod` 4) == 0) $ do
                  open <- isStreamOpen conn sid
                  when open $ sendStream conn sid True hdrbdy
              loop hdrbdy
