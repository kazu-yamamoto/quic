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
import Data.IORef
import System.Console.GetOpt
import System.Environment
import System.Exit

import Network.QUIC
import Network.TLS.QUIC

import Common
import H3

data Options = Options {
    optDebugLog   :: Bool
  , optShow       :: Bool
  , optQLogDir    :: Maybe FilePath
  , optKeyLogFile :: Maybe FilePath
  , optGroups     :: Maybe String
  , optValidate   :: Bool
  , optHQ         :: Bool
  , optVerNego    :: Bool
  , optResumption :: Bool
  , opt0RTT       :: Bool
  , optRetry      :: Bool
  , optQuantum    :: Bool
  , optMigration  :: Maybe Migration
  , optPacketSize :: Maybe Int
  } deriving Show

defaultOptions :: Options
defaultOptions = Options {
    optDebugLog   = False
  , optShow       = False
  , optQLogDir    = Nothing
  , optKeyLogFile = Nothing
  , optGroups     = Nothing
  , optHQ         = False
  , optValidate   = False
  , optVerNego    = False
  , optResumption = False
  , opt0RTT       = False
  , optRetry      = False
  , optQuantum    = False
  , optMigration  = Nothing
  , optPacketSize = Nothing
  }

usage :: String
usage = "Usage: client [OPTION] addr port"

options :: [OptDescr (Options -> Options)]
options = [
    Option ['d'] ["debug"]
    (NoArg (\o -> o { optDebugLog = True }))
    "print debug info"
  , Option ['v'] ["show-content"]
    (NoArg (\o -> o { optShow = True }))
    "print downloaded content"
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
  , Option ['s'] ["packet-size"]
    (ReqArg (\n o -> o { optPacketSize = Just (read n) }) "<int>")
    "specify QUIC packet size (UDP payload size)"
  , Option ['V'] ["vernego"]
    (NoArg (\o -> o { optVerNego = True }))
    "try version negotiation"
  , Option ['R'] ["resumption"]
    (NoArg (\o -> o { optResumption = True }))
    "try session resumption"
  , Option ['Z'] ["0rtt"]
    (NoArg (\o -> o { opt0RTT = True }))
    "try sending early data"
  , Option ['S'] ["stateless-retry"]
    (NoArg (\o -> o { optRetry = True }))
    "check stateless retry"
  , Option ['Q'] ["quantum"]
    (NoArg (\o -> o { optQuantum = True }))
    "try sending large Initials"
  , Option ['M'] ["change-server-cid"]
    (NoArg (\o -> o { optMigration = Just ChangeServerCID }))
    "use a new server CID"
  , Option ['N'] ["change-client-cid"]
    (NoArg (\o -> o { optMigration = Just ChangeClientCID }))
    "use a new client CID"
  , Option ['B'] ["nat-rebinding"]
    (NoArg (\o -> o { optMigration = Just NATRebiding }))
    "use a new local port"
  , Option ['A'] ["address-mobility"]
    (NoArg (\o -> o { optMigration = Just MigrateTo }))
    "use a new address and a new server CID"
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

data Aux = Aux {
    auxPath :: String
  , auxAuthority :: String
  , auxDebug :: String -> IO ()
  , auxShow :: ByteString -> IO ()
  , auxCheckClose :: IO Bool
  }

type Cli = Aux -> Connection -> IO ()

main :: IO ()
main = do
    args <- getArgs
    (opts@Options{..}, ips) <- clientOpts args
    let ipslen = length ips
    when (ipslen /= 2 && ipslen /= 3) $
        showUsageAndExit "cannot recognize <addr> and <port>\n"
    cref <- newIORef False
    let path | ipslen == 3 = ips !! 2
             | otherwise   = "/"
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
          , ccPacketSize = optPacketSize
          , ccDebugLog   = optDebugLog
          , ccConfig     = defaultConfig {
                confVersions   = if optVerNego then
                                   GreasingVersion : confVersions defaultConfig
                                 else
                                   confVersions defaultConfig
              , confParameters = if optQuantum then
                                   defaultParameters {
                                       greaseParameter = Just (BS.pack (replicate 1200 0))
                                     }
                                 else
                                   defaultParameters
              , confKeyLog     = getLogger optKeyLogFile
              , confGroups     = getGroups optGroups
              , confQLog       = optQLogDir
              , confHooks      = defaultHooks {
                    onCloseReceived = writeIORef cref True
                  }
              }
          }
        debug | optDebugLog = putStrLn
              | otherwise   = \_ -> return ()
        showContent | optShow = C8.putStrLn
                    | otherwise = \_ -> return ()
        aux = Aux {
            auxPath = path
          , auxAuthority = addr
          , auxDebug = debug
          , auxShow = showContent
          , auxCheckClose = readIORef cref
          }
    runClient conf opts aux

runClient :: ClientConfig -> Options -> Aux -> IO ()
runClient conf opts@Options{..} aux@Aux{..} = do
    auxDebug "------------------------"
    (info1,info2,res,mig, client') <- runQUICClient conf $ \conn -> do
        i1 <- getConnectionInfo conn
        let client = case alpn i1 of
              Just proto | "hq" `BS.isPrefixOf` proto -> clientHQ
              _                                       -> clientH3
        m <- case optMigration of
          Nothing   -> return False
          Just mtyp -> do
              x <- migration conn mtyp
              auxDebug $ "Migration by " ++ show mtyp
              return x
        client aux conn
        i2 <- getConnectionInfo conn
        r <- getResumptionInfo conn
        return (i1, i2, r, m, client)
    if optVerNego then do
        putStrLn "Result: (V) version negotiation ... OK"
        exitSuccess
      else if optQuantum then do
        putStrLn "Result: (Q) quantum ... OK"
        exitSuccess
      else if optResumption then do
        if isResumptionPossible res then do
            info3 <- runClient2 conf opts aux res client'
            if handshakeMode info3 == PreSharedKey then do
                putStrLn "Result: (R) TLS resumption ... OK"
                exitSuccess
              else do
                putStrLn "Result: (R) TLS resumption ... NG"
                exitFailure
          else do
            putStrLn "Result: (R) TLS resumption ... NG"
            exitFailure
      else if opt0RTT then do
        if is0RTTPossible res then do
            info3 <- runClient2 conf opts aux res client'
            if handshakeMode info3 == RTT0 then do
                putStrLn "Result: (Z) 0-RTT ... OK"
                exitSuccess
              else do
                putStrLn "Result: (Z) 0-RTT ... NG"
                exitFailure
          else do
            putStrLn "Result: (Z) 0-RTT ... NG"
            exitFailure
      else if optRetry then do
        if retry info1 then do
            putStrLn "Result: (S) retry ... OK"
            exitSuccess
          else do
            putStrLn "Result: (S) retry ... NG"
            exitFailure
      else case optMigration of
             Just ChangeServerCID -> do
                 let changed = remoteCID info1 /= remoteCID info2
                 if mig && remoteCID info1 /= remoteCID info2 then do
                     putStrLn "Result: (M) change server CID ... OK"
                     exitSuccess
                   else do
                     putStrLn $ "Result: (M) change server CID ... NG " ++ show (mig,changed)
                     exitFailure
             Just ChangeClientCID -> do
                 let changed = localCID info1 /= localCID info2
                 if mig && changed then do
                     putStrLn "Result: (N) change client CID ... OK"
                     exitSuccess
                   else do
                     putStrLn $ "Result: (N) change client CID ... NG " ++ show (mig,changed)
                     exitFailure
             Just NATRebiding -> do
                 putStrLn "Result: (B) NAT rebinding ... OK"
                 exitSuccess
             Just MigrateTo -> do
                 let changed = remoteCID info1 /= remoteCID info2
                 if mig && changed then do
                     putStrLn "Result: (A) address mobility ... OK"
                     exitSuccess
                   else do
                     putStrLn $ "Result: (A) address mobility ... NG " ++ show (mig,changed)
                     exitFailure
             Nothing -> do
                 putStrLn "Result: (H) handshake ... OK"
                 putStrLn "Result: (D) stream data ... OK"
                 closeReceived <- auxCheckClose
                 when closeReceived $ putStrLn "Result: (C) close received ... OK"
                 exitSuccess

runClient2 :: ClientConfig -> Options -> Aux -> ResumptionInfo -> Cli
           -> IO ConnectionInfo
runClient2 conf Options{..} aux@Aux{..} res client = do
    threadDelay 100000
    auxDebug "<<<< next connection >>>>"
    auxDebug "------------------------"
    runQUICClient conf' $ \conn -> do
        void $ client aux conn
        getConnectionInfo conn
  where
    conf' = conf {
        ccResumption = res
      , ccUse0RTT    = opt0RTT && is0RTTPossible res
      }

clientHQ :: Cli
clientHQ Aux{..} conn = do
    let cmd = C8.pack ("GET " ++ auxPath ++ "\r\n")
    s <- stream conn
    sendStream s cmd
    shutdownStream s
    loop s
  where
    loop s = do
        bs <- recvStream s 1024
        if bs == "" then do
            auxDebug "Connection finished"
            closeStream conn s
            getConnectionStats conn >>= print
          else do
            auxShow bs
            loop s

clientH3 :: Cli
clientH3 Aux{..} conn = do
    hdrblk <- taglen 1 <$> qpackClient auxAuthority
    s0 <- stream conn
    s2 <- unidirectionalStream conn
    s6 <- unidirectionalStream conn
    s10 <- unidirectionalStream conn
    -- 0: control, 4 settings
    sendStream s2 (BS.pack [0,4,8,1,80,0,6,128,0,128,0])
    -- 2: from encoder to decoder
    sendStream s6 (BS.pack [2])
    -- 3: from decoder to encoder
    sendStream s10 (BS.pack [3])
    sendStream s0 hdrblk
    shutdownStream s0
    loop s0
  where
    loop s0 = do
        bs <- recvStream s0 1024
        auxDebug $ "SID: " ++ show (streamId s0)
        if bs == "" then do
            auxDebug "Connection finished"
            closeStream conn s0
            getConnectionStats conn >>= print
          else do
            auxShow bs
            loop s0
