{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE StrictData #-}

module H3 (
    qpackClient,
    qpackServer,
    taglen,
    html,
) where

import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Word
import Network.HPACK.Internal

import Network.QUIC.Internal

name :: ByteString
name = "HaskellQuic/0.0.0"

qpackServer :: IO ByteString
qpackServer = do
    let status = 0b11000000 .|. 25 -- :status: 200
        ct = 0b11000000 .|. 52 -- content-type: text/html; charset=utf8
    server <- encStr 92 name
    return $ BS.concat [BS.pack [0, 0, status, ct], server]

qpackClient :: ByteString -> String -> IO ByteString
qpackClient path authority = do
    let method = 0b11000000 .|. 17 -- :method: GET
        scheme = 0b11000000 .|. 22 -- :scheme: http
    path' <- encStr 1 path
    auth <- encStr 0 $ C8.pack authority
    ua <- encStr 95 name
    return $
        BS.concat
            [ BS.pack [0, 0, method, scheme]
            , path'
            , auth
            , ua
            ]

encStr :: Int -> ByteString -> IO ByteString
encStr idx val = do
    k <- setQpackTag 0b01010000 <$> encodeInteger 4 idx
    v <- encodeHuffman val
    vlen <- setQpackTag 0b10000000 <$> encodeInteger 7 (BS.length v)
    return $ BS.concat [k, vlen, v]

setQpackTag :: Word8 -> ByteString -> ByteString
setQpackTag tag bs = BS.cons (tag .|. BS.head bs) (BS.tail bs)

taglen :: Word8 -> ByteString -> ByteString
taglen i bs = BS.concat [tag, len, bs]
  where
    tag = BS.singleton i
    len = encodeInt $ fromIntegral $ BS.length bs

html :: ByteString
html =
    "<html><head><title>Welcome to QUIC in Haskell</title></head><body><p>Welcome to QUIC in Haskell.</p></body></html>"
