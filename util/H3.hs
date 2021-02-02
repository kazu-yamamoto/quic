{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE StrictData #-}

module H3 (
    qpackClient
  , qpackServer
  , taglen
  , html
  , makeProtos
  ) where

import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Word
import Network.HPACK.Internal

import Network.QUIC
import Network.QUIC.Internal

name :: ByteString
name = "HaskellQuic/0.0.0"

qpackServer :: IO ByteString
qpackServer = do
    let status = 0b1100_0000 .|. 25 -- :status: 200
        ct     = 0b1100_0000 .|. 52 -- content-type: text/html; charset=utf8
    server <- encStr 92 name
    return $ BS.concat [BS.pack[0,0,status,ct],server]

qpackClient :: String -> String -> IO ByteString
qpackClient path authority = do
    let method = 0b1100_0000 .|. 17 -- :method: GET
        scheme = 0b1100_0000 .|. 22 -- :scheme: http
    path' <- encStr  1 $ C8.pack path
    auth  <- encStr  0 $ C8.pack authority
    ua    <- encStr 95 name
    return $ BS.concat [BS.pack [0,0,method,scheme]
                       ,path'
                       ,auth
                       ,ua]

encStr :: Int -> ByteString -> IO ByteString
encStr idx val = do
    k <- setQpackTag 0b0101_0000 <$> encodeInteger 4 idx
    v <- encodeHuffman val
    vlen <- setQpackTag 0b1000_0000 <$> encodeInteger 7 (BS.length v)
    return $ BS.concat [k,vlen,v]

setQpackTag :: Word8 -> ByteString -> ByteString
setQpackTag tag bs = BS.cons (tag .|. BS.head bs) (BS.tail bs)

taglen :: Word8 -> ByteString -> ByteString
taglen i bs = BS.concat [tag,len,bs]
  where
    tag = BS.singleton i
    len = encodeInt $ fromIntegral $ BS.length bs

html :: ByteString
html = "<html><head><title>Welcome to QUIC in Haskell</title></head><body><p>Welcome to QUIC in Haskell. This server asks clients to retry if no token/retry_token is provided. HTTP 0.9, HTTP/3 and QPACK implementations are a toy and hard-coded. No path validation at this moment.</p></body></html>"

makeProtos :: Version -> (ByteString, ByteString)
makeProtos Version1 = ("h3","hq-interop")
makeProtos ver = (h3X,hqX)
  where
    verbs = C8.pack $ show $ fromVersion ver
    h3X = "h3-" `BS.append` verbs
    hqX = "hq-" `BS.append` verbs
