module Common (
    getGroups
  , getLogger
  ) where

import Data.Maybe
import Network.TLS

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
getGroups Nothing   = confGroups defaultConfig
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
