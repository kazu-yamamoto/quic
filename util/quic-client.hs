{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.UnixTime
import Data.Word
import Foreign.C.Types
import Network.TLS.QUIC
import System.Console.GetOpt
import System.Environment
import System.Exit
import System.IO
import Text.Printf
import qualified UnliftIO.Timeout as T

import ClientX
import Common
import Network.QUIC
import Network.QUIC.Client
import Network.QUIC.Internal hiding (RTT0)

data Options = Options
    { optDebugLog :: Bool
    , optShow :: Bool
    , optQLogDir :: Maybe FilePath
    , optKeyLogFile :: Maybe FilePath
    , optGroups :: Maybe String
    , optValidate :: Bool
    , optHQ :: Bool
    , optVerNego :: Bool
    , optResumption :: Bool
    , opt0RTT :: Bool
    , optRetry :: Bool
    , optQuantum :: Bool
    , optInteractive :: Bool
    , optMigration :: Maybe ConnectionControl
    , optPacketSize :: Maybe Int
    , optPerformance :: Word64
    , optNumOfReqs :: Int
    }
    deriving (Show)

defaultOptions :: Options
defaultOptions =
    Options
        { optDebugLog = False
        , optShow = False
        , optQLogDir = Nothing
        , optKeyLogFile = Nothing
        , optGroups = Nothing
        , optHQ = False
        , optValidate = False
        , optVerNego = False
        , optResumption = False
        , opt0RTT = False
        , optRetry = False
        , optQuantum = False
        , optInteractive = False
        , optMigration = Nothing
        , optPacketSize = Nothing
        , optPerformance = 0
        , optNumOfReqs = 1
        }

usage :: String
usage = "Usage: quic-client [OPTION] addr port [path]"

options :: [OptDescr (Options -> Options)]
options =
    [ Option
        ['d']
        ["debug"]
        (NoArg (\o -> o{optDebugLog = True}))
        "print debug info"
    , Option
        ['v']
        ["show-content"]
        (NoArg (\o -> o{optShow = True}))
        "print downloaded content"
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
        "specify groups"
    , Option
        ['e']
        ["validate"]
        (NoArg (\o -> o{optValidate = True}))
        "validate server's certificate"
    , Option
        ['9']
        ["hq"]
        (NoArg (\o -> o{optHQ = True}))
        "prefer hq (HTTP/0.9)"
    , Option
        ['s']
        ["packet-size"]
        (ReqArg (\n o -> o{optPacketSize = Just (read n)}) "<size>")
        "specify QUIC packet size (UDP payload size)"
    , Option
        ['i']
        ["interactive"]
        (NoArg (\o -> o{optInteractive = True}))
        "enter interactive mode"
    , Option
        ['V']
        ["vernego"]
        (NoArg (\o -> o{optVerNego = True}))
        "try version negotiation"
    , Option
        ['R']
        ["resumption"]
        (NoArg (\o -> o{optResumption = True}))
        "try session resumption"
    , Option
        ['Z']
        ["0rtt"]
        (NoArg (\o -> o{opt0RTT = True}))
        "try sending early data"
    , Option
        ['S']
        ["stateless-retry"]
        (NoArg (\o -> o{optRetry = True}))
        "check stateless retry"
    , Option
        ['Q']
        ["quantum"]
        (NoArg (\o -> o{optQuantum = True}))
        "try sending large Initials"
    , Option
        ['M']
        ["change-server-cid"]
        (NoArg (\o -> o{optMigration = Just ChangeServerCID}))
        "use a new server CID"
    , Option
        ['N']
        ["change-client-cid"]
        (NoArg (\o -> o{optMigration = Just ChangeClientCID}))
        "use a new client CID"
    , Option
        ['B']
        ["nat-rebinding"]
        (NoArg (\o -> o{optMigration = Just NATRebinding}))
        "use a new local port"
    , Option
        ['A']
        ["address-mobility"]
        (NoArg (\o -> o{optMigration = Just ActiveMigration}))
        "use a new address and a new server CID"
    , Option
        ['t']
        ["performance"]
        (ReqArg (\n o -> o{optPerformance = read n}) "<size>")
        "measure performance"
    , Option
        ['n']
        ["number-of-requests"]
        (ReqArg (\n o -> o{optNumOfReqs = read n}) "<n>")
        "specify the number of requests"
    ]

showUsageAndExit :: String -> IO a
showUsageAndExit msg = do
    putStrLn msg
    putStrLn $ usageInfo usage options
    exitFailure

clientOpts :: [String] -> IO (Options, [String])
clientOpts argv =
    case getOpt Permute options argv of
        (o, n, []) -> return (foldl (flip id) defaultOptions o, n)
        (_, _, errs) -> showUsageAndExit $ concat errs

main :: IO ()
main = do
    args <- getArgs
    (opts@Options{..}, ips) <- clientOpts args
    (host, port, paths) <- case ips of
        [] -> showUsageAndExit usage
        _ : [] -> showUsageAndExit usage
        h : p : [] -> return (h, p, ["/"])
        h : p : ps -> return (h, p, C8.pack <$> ps)
    cmvar <- newEmptyMVar
    let ccalpn ver
            | optPerformance /= 0 = return $ Just ["perf"]
            | otherwise =
                let (h3X, hqX) = makeProtos ver
                    protos
                        | optHQ = [hqX, h3X]
                        | otherwise = [h3X, hqX]
                 in return $ Just protos
        gvers vers
            | optVerNego = GreasingVersion : vers
            | otherwise = vers
        setTPQuantum params
            | optQuantum =
                let bs = BS.replicate 1200 0
                 in params{grease = Just bs}
            | otherwise = params
        cc0 = defaultClientConfig
        cc =
            cc0
                { ccServerName = host
                , ccPortName = port
                , ccALPN = ccalpn
                , ccValidate = optValidate
                , ccPacketSize = optPacketSize
                , ccDebugLog = optDebugLog
                , ccVersions = gvers $ ccVersions cc0
                , ccParameters = setTPQuantum $ ccParameters cc0
                , ccKeyLog = getLogger optKeyLogFile
                , ccGroups = getGroups (ccGroups cc0) optGroups
                , ccQLog = optQLogDir
                , ccHooks =
                    defaultHooks
                        { onCloseCompleted = putMVar cmvar ()
                        }
                }
        debug
            | optDebugLog = putStrLn
            | otherwise = \_ -> return ()
        showContent
            | optShow = C8.putStrLn
            | otherwise = \_ -> return ()
        aux =
            Aux
                { auxAuthority = host
                , auxDebug = debug
                , auxShow = showContent
                , auxCheckClose = do
                    mx <- T.timeout 1000000 $ takeMVar cmvar
                    case mx of
                        Nothing -> return False
                        _ -> return True
                }
    runClient cc opts aux paths

runClient :: ClientConfig -> Options -> Aux -> [ByteString] -> IO ()
runClient cc opts@Options{..} aux@Aux{..} paths = do
    auxDebug "------------------------"
    (info1, info2, res, mig, client') <- run cc $ \conn -> do
        i1 <- getConnectionInfo conn
        let client = case alpn i1 of
                Just proto
                    | "hq" `BS.isPrefixOf` proto -> clientHQ optNumOfReqs
                    | "h3" `BS.isPrefixOf` proto -> clientH3 optNumOfReqs
                _ -> clientPF optPerformance
        m <- case optMigration of
            Nothing -> return False
            Just mtyp -> do
                x <- controlConnection conn mtyp
                auxDebug $ "Migration by " ++ show mtyp
                return x
        t1 <- getUnixTime
        if optInteractive
            then do
                console aux paths client conn
            else do
                client aux paths conn
        stats <- getConnectionStats conn
        print stats
        t2 <- getUnixTime
        i2 <- getConnectionInfo conn
        r <- getResumptionInfo conn
        printThroughput t1 t2 stats
        return (i1, i2, r, m, client)
    if
        | optVerNego -> do
            putStrLn "Result: (V) version negotiation ... OK"
            exitSuccess
        | optQuantum -> do
            putStrLn "Result: (Q) quantum ... OK"
            exitSuccess
        | optResumption -> do
            if isResumptionPossible res
                then do
                    info3 <- runClient2 cc opts aux paths res client'
                    if handshakeMode info3 == PreSharedKey
                        then do
                            putStrLn "Result: (R) TLS resumption ... OK"
                            exitSuccess
                        else do
                            putStrLn "Result: (R) TLS resumption ... NG"
                            exitFailure
                else do
                    putStrLn "Result: (R) TLS resumption ... NG"
                    exitFailure
        | opt0RTT -> do
            if is0RTTPossible res
                then do
                    info3 <- runClient2 cc opts aux paths res client'
                    if handshakeMode info3 == RTT0
                        then do
                            putStrLn "Result: (Z) 0-RTT ... OK"
                            exitSuccess
                        else do
                            putStrLn "Result: (Z) 0-RTT ... NG"
                            exitFailure
                else do
                    putStrLn "Result: (Z) 0-RTT ... NG"
                    exitFailure
        | optRetry -> do
            if retry info1
                then do
                    putStrLn "Result: (S) retry ... OK"
                    exitSuccess
                else do
                    putStrLn "Result: (S) retry ... NG"
                    exitFailure
        | otherwise -> case optMigration of
            Just ChangeServerCID -> do
                let changed = remoteCID info1 /= remoteCID info2
                if mig && remoteCID info1 /= remoteCID info2
                    then do
                        putStrLn "Result: (M) change server CID ... OK"
                        exitSuccess
                    else do
                        putStrLn $ "Result: (M) change server CID ... NG " ++ show (mig, changed)
                        exitFailure
            Just ChangeClientCID -> do
                let changed = localCID info1 /= localCID info2
                if mig && changed
                    then do
                        putStrLn "Result: (N) change client CID ... OK"
                        exitSuccess
                    else do
                        putStrLn $ "Result: (N) change client CID ... NG " ++ show (mig, changed)
                        exitFailure
            Just NATRebinding -> do
                putStrLn "Result: (B) NAT rebinding ... OK"
                exitSuccess
            Just ActiveMigration -> do
                let changed = remoteCID info1 /= remoteCID info2
                if mig && changed
                    then do
                        putStrLn "Result: (A) address mobility ... OK"
                        exitSuccess
                    else do
                        putStrLn $ "Result: (A) address mobility ... NG " ++ show (mig, changed)
                        exitFailure
            Nothing -> do
                putStrLn "Result: (H) handshake ... OK"
                putStrLn "Result: (D) stream data ... OK"
                closeCompleted <- auxCheckClose
                when closeCompleted $ putStrLn "Result: (C) close completed ... OK"
                case alpn info1 of
                    Nothing -> return ()
                    Just alpn ->
                        when ("h3" `BS.isPrefixOf` alpn) $
                            putStrLn "Result: (3) H3 transaction ... OK"
                exitSuccess

runClient2
    :: ClientConfig
    -> Options
    -> Aux
    -> [ByteString]
    -> ResumptionInfo
    -> Cli
    -> IO ConnectionInfo
runClient2 cc Options{..} aux@Aux{..} paths res client = do
    threadDelay 100000
    auxDebug "<<<< next connection >>>>"
    auxDebug "------------------------"
    run cc' $ \conn -> do
        void $ client aux paths conn
        getConnectionInfo conn
  where
    cc' =
        cc
            { ccResumption = res
            , ccUse0RTT = opt0RTT && is0RTTPossible res
            }

printThroughput :: UnixTime -> UnixTime -> ConnectionStats -> IO ()
printThroughput t1 t2 stats =
    printf
        "Throughput %.2f Mbps (%d bytes in %d msecs)\n"
        bytesPerSeconds
        (rxBytes stats)
        millisecs
  where
    UnixDiffTime (CTime s) u = t2 `diffUnixTime` t1
    millisecs :: Int
    millisecs = fromIntegral s * 1000 + fromIntegral u `div` 1000
    bytesPerSeconds :: Double
    bytesPerSeconds =
        fromIntegral (rxBytes stats)
            * (1000 :: Double)
            * 8
            / fromIntegral millisecs
            / 1024
            / 1024

console :: Aux -> [ByteString] -> Cli -> Connection -> IO ()
console aux paths client conn = do
    waitEstablished conn
    putStrLn "q -- quit"
    putStrLn "g -- get"
    putStrLn "p -- ping"
    putStrLn "n -- NAT rebinding"
    loop
  where
    loop = do
        hSetBuffering stdout NoBuffering
        putStr "> "
        hSetBuffering stdout LineBuffering
        l <- getLine
        case l of
            "q" -> putStrLn "bye"
            "g" -> do
                mapM_ (\p -> putStrLn $ "GET " ++ C8.unpack p) paths
                _ <- forkIO $ client aux paths conn
                loop
            "p" -> do
                putStrLn "Ping"
                sendFrames conn RTT1Level [Ping]
                loop
            "n" -> do
                controlConnection conn NATRebinding >>= print
                loop
            _ -> do
                putStrLn "No such command"
                loop
