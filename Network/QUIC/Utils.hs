{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Utils where

import Control.Exception
import Control.Monad (replicateM)
import qualified Data.ByteString as BS
import Data.ByteString.Base16
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Internal (ByteString (..))
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as Short
import Data.Char (chr)
import Data.List (foldl')
import Data.Word
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (Ptr, plusPtr)
import System.Random (randomIO)

-- GHC 8.0 does not provide fromRight.
fromRight :: b -> Either a b -> b
fromRight _ (Right b) = b
fromRight b _ = b

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
totalLen = foldl' (\n bs -> n + BS.length bs) 0

sum' :: (Functor f, Foldable f) => f Int -> Int
sum' = foldl' (+) 0

withByteString :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteString (PS fptr off _) f = withForeignPtr fptr $ \ptr ->
    f (ptr `plusPtr` off)

shortpack :: String -> ShortByteString
shortpack = Short.toShort . C8.pack

ignore :: SomeException -> IO ()
ignore _ = return ()
