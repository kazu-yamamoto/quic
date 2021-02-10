{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Utils where

import Control.Monad (replicateM)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Base16
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as Short
import Data.Char (chr)
import Data.Either (fromRight)
import Data.List (foldl')
import Data.Word
import System.Random (randomIO)

dec16 :: ByteString -> ByteString
dec16 = fromRight "" . decode

enc16 :: ByteString -> ByteString
enc16 = encode

dec16s :: ShortByteString -> ShortByteString
dec16s = Short.toShort . fromRight "" . decode . Short.fromShort

enc16s :: ShortByteString -> ShortByteString
enc16s = Short.toShort . encode . Short.fromShort

shortToString :: ShortByteString -> String
shortToString = map (chr . fromIntegral) . Short.unpack

getRandomOneByte :: IO Word8
getRandomOneByte = randomIO

getRandomBytes :: Int -> IO ShortByteString
getRandomBytes n = Short.pack <$> replicateM n getRandomOneByte

{-# INLINE totalLen #-}
totalLen :: [ByteString] -> Int
totalLen = foldl' (+) 0 . map BS.length

sum' :: (Functor f, Foldable f) => f Int -> Int
sum' = foldl' (+) 0
