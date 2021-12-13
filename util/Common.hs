{-# LANGUAGE OverloadedStrings #-}

module Common (
    getGroups
  , getLogger
  , makeProtos
  ) where

import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Maybe
import Network.TLS hiding (Version)

import Network.QUIC.Internal

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

getGroups :: [Group] -> Maybe String -> [Group]
getGroups grps Nothing   = grps
getGroups _    (Just gs) = mapMaybe (`lookup` namedGroups) $ split ',' gs

split :: Char -> String -> [String]
split _ "" = []
split c s = case break (c==) s of
    ("",r)  -> split c (tail r)
    (s',"") -> [s']
    (s',r)  -> s' : split c (tail r)

getLogger :: Maybe FilePath -> (String -> IO ())
getLogger Nothing     = \_ -> return ()
getLogger (Just file) = \msg -> appendFile file (msg ++ "\n")

makeProtos :: Version -> (ByteString, ByteString)
makeProtos Version1 = ("h3","hq-interop")
makeProtos ver = (h3X,hqX)
  where
    verbs = C8.pack $ show $ fromVersion ver
    h3X = "h3-" `BS.append` verbs
    hqX = "hq-" `BS.append` verbs

fromVersion :: Version -> Int
fromVersion (Version ver) = fromIntegral (0x000000ff .&. ver)
