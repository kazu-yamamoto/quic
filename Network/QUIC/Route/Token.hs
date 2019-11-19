{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Route.Token (
    RetryToken(..)
  , encryptRetryToken
  , decryptRetryToken
  , TokenSecret(..)
  , generateTokenSecret
  ) where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS
import Data.IORef
import Network.ByteOrder

import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Transport

----------------------------------------------------------------

data RetryToken = RetryToken {
    tokenVersion :: Version
  , localCID     :: CID
  , remoteCID    :: CID
  , origLocalCID :: CID
  }

data TokenSecret = TokenSecret {
    tokenIV      :: IV
  , tokenKey     :: Key
  , tokenCounter :: IORef Int64
  }

----------------------------------------------------------------

generateTokenSecret :: IO TokenSecret
generateTokenSecret = TokenSecret <$> genServerIV
                                  <*> genServerKey
                                  <*> newIORef 0

----------------------------------------------------------------

serverKeyLength :: Int
serverKeyLength = 32

serverIVLength :: Int
serverIVLength = 8

serverEncrypt :: Key -> Nonce -> PlainText -> AddDat -> CipherText
serverEncrypt = aes256gcmEncrypt

serverDecrypt :: Key -> Nonce -> CipherText -> AddDat -> Maybe PlainText
serverDecrypt = aes256gcmDecrypt

genServerKey :: IO Key
genServerKey = Key <$> getRandomBytes serverKeyLength

genServerIV :: IO IV
genServerIV = IV <$> getRandomBytes serverIVLength

makeNonce1 :: IV -> Int64 -> Nonce
makeNonce1 iv n = makeNonce2 iv seqnum
  where
    seqnum = encodeInt8 n

makeNonce2 :: IV -> ByteString -> Nonce
makeNonce2 (IV iv) seqnum = Nonce nonce
  where
    nonce = iv `bsXOR` seqnum

serverAddDat :: AddDat
serverAddDat = AddDat ""

encryptRetryToken :: TokenSecret -> RetryToken -> IO Token
encryptRetryToken TokenSecret{..} retryToken = do
    plain <- encodeRetryToken retryToken
    n <- atomicModifyIORef' tokenCounter (\i -> (i+1, i))
    let nonce = makeNonce1 tokenIV n
    return $ serverEncrypt tokenKey nonce plain serverAddDat

-- seqnum = 8 bytes
-- tag = 16 bytes
-- 1 + 1 + 1 + 8
decryptRetryToken :: TokenSecret -> Token -> IO (Maybe RetryToken)
decryptRetryToken TokenSecret{..} bs
  | BS.length bs < 35 = return Nothing
  | otherwise = do
        let (seqnum,cipher) = BS.splitAt 8 bs
            nonce = makeNonce2 tokenIV seqnum
            mplain = serverDecrypt tokenKey nonce cipher serverAddDat
        case mplain of
          Nothing    -> return Nothing
          Just plain -> Just <$> decodeRetryToken plain -- fixme: buffer overrun

----------------------------------------------------------------

encodeRetryToken :: RetryToken -> IO Token
encodeRetryToken (RetryToken ver lCID rCID oCID) = withWriteBuffer 256 $ \wbuf -> do
    write32 wbuf $ encodeVersion ver
    let (lcid, llen) = unpackCID lCID
    write8 wbuf llen
    copyShortByteString wbuf lcid
    let (rcid, rlen) = unpackCID rCID
    write8 wbuf rlen
    copyShortByteString wbuf rcid
    let (ocid, olen) = unpackCID oCID
    write8 wbuf olen
    copyShortByteString wbuf ocid

decodeRetryToken :: ByteString -> IO RetryToken
decodeRetryToken bs = withReadBuffer bs $ \rbuf -> do
    ver  <- decodeVersion <$> read32 rbuf
    llen <- fromIntegral <$> read8 rbuf
    lCID <- makeCID <$> extractShortByteString rbuf llen
    rlen <- fromIntegral <$> read8 rbuf
    rCID <- makeCID <$> extractShortByteString rbuf rlen
    olen <- fromIntegral <$> read8 rbuf
    oCID <- makeCID <$> extractShortByteString rbuf olen
    return $ RetryToken ver lCID rCID oCID
