module Common (
    getGroups
  , getLogger
  , getDirLogger
  , getStdoutLogger
  ) where

import Control.Concurrent
import qualified Control.Exception as E
import Data.ByteString.Base16 (encode)
import qualified Data.ByteString.Char8 as C8
import Data.Default.Class
import Data.Maybe
import Network.TLS
import System.FilePath

import Network.QUIC

namedGroups :: [(String, Group)]
namedGroups =
    [ ("ffdhe2048", FFDHE2048)
    , ("ffdhe3072", FFDHE3072)
    , ("ffdhe4096", FFDHE4096)
    , ("ffdhe6144", FFDHE6144)
    , ("ffdhe8192", FFDHE8192)
    , ("p256",      P256)
    , ("p384",      P384)
    , ("p521",      P521)
    , ("x25519",    X25519)
    , ("x448",      X448)
    ]

getGroups :: Maybe String -> [Group]
getGroups Nothing   = supportedGroups def
getGroups (Just gs) = catMaybes $ map (`lookup` namedGroups) $ split ',' gs

split :: Char -> String -> [String]
split _ "" = []
split c s = case break (c==) s of
    ("",r)  -> split c (tail r)
    (s',"") -> [s']
    (s',r)  -> s' : split c (tail r)

getLogger :: Maybe FilePath -> (String -> IO ())
getLogger Nothing     = \_ -> return ()
getLogger (Just file) = \msg -> appendFile file (msg ++ "\n")

getStdoutLogger :: Bool -> (CID -> String -> IO ())
getStdoutLogger False = \_ _ -> return ()
getStdoutLogger True  = \_ msg -> putStr msg

getDirLogger :: Maybe FilePath -> String -> (CID -> String -> IO ())
getDirLogger Nothing    _      = \_ _ -> return ()
getDirLogger (Just dir) suffix = \cid msg -> do
    let filename = C8.unpack (encode (fromCID cid)) ++ suffix
        logfile = dir </> filename
    appendFile logfile msg `E.catch` \(E.SomeException _) -> do
        threadDelay 1000
        appendFile logfile msg
