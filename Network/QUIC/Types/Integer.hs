{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC.Types.Integer (
    encodeInt
  , encodeInt8
  , encodeInt'
  , encodeInt'2
  , decodeInt
  , decodeInt'
  ) where

import Data.ByteString.Internal (unsafeCreate)
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe (unsafeDupablePerformIO)

import Network.QUIC.Imports

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Network.QUIC.Utils

----------------------------------------------------------------

-- |
-- >>> enc16 $ encodeInt 151288809941952652
-- "c2197c5eff14e88c"
-- >>> enc16 $ encodeInt 494878333
-- "9d7f3e7d"
-- >>> enc16 $ encodeInt 15293
-- "7bbd"
-- >>> enc16 $ encodeInt 37
-- "25"
encodeInt :: Int64  -> ByteString
encodeInt i = unsafeCreate n $ \p -> do
    let p' = p `plusPtr` (n - 1)
    go tag n i p'
  where
    (tag,n) = tagLen i
{-# NOINLINE encodeInt #-}

encodeInt8 :: Int64  -> ByteString
encodeInt8 i = unsafeCreate n $ \p -> do
    let p' = p `plusPtr` (n - 1)
    go tag n i p'
  where
    n = 8
    tag = 0b11000000
{-# NOINLINE encodeInt8 #-}

go :: Word8 -> Int -> Int64 -> Ptr Word8 -> IO ()
go _   0 _ _ = return ()
go tag 1 x p = poke p (tag .|. fromIntegral x)
go tag n x p = do
    poke p (fromIntegral x)
    let n' = n - 1
        x' = x .>>. 8
        p' = p `plusPtr` (-1)
    go tag n' x' p'

tagLen :: Int64 -> (Word8, Int)
tagLen i | i <=         63 = (0b00000000, 1)
         | i <=      16383 = (0b01000000, 2)
         | i <= 1073741823 = (0b10000000, 4)
         | otherwise       = (0b11000000, 8)

encodeInt' :: WriteBuffer -> Int64 -> IO ()
encodeInt' wbuf i = mapM_ (write8 wbuf) ws
  where
    (tag,n) = tagLen i
    ws = decomp tag n [] i

encodeInt'2 :: WriteBuffer -> Int64 -> IO ()
encodeInt'2 wbuf i = do
    let ws = decomp 0b01000000 2 [] i
    mapM_ (write8 wbuf) ws

decomp :: Word8 -> Int -> [Word8] -> Int64 -> [Word8]
decomp _   0 ws _ = ws
decomp tag 1 ws x = w:ws
  where
    w  = fromIntegral x .|. tag
decomp tag n ws x = decomp tag (n-1) (w:ws) x'
  where
    x' = x .>>. 8
    w  = fromIntegral x

----------------------------------------------------------------

-- |
-- >>> decodeInt (dec16 "c2197c5eff14e88c")
-- 151288809941952652
-- >>> decodeInt (dec16 "9d7f3e7d")
-- 494878333
-- >>> decodeInt (dec16 "7bbd")
-- 15293
-- >>> decodeInt (dec16 "25")
-- 37
decodeInt :: ByteString -> Int64
decodeInt bs = unsafeDupablePerformIO $ withReadBuffer bs decodeInt'
{-# NOINLINE decodeInt #-}

decodeInt' :: ReadBuffer -> IO Int64
decodeInt' rbuf = do
    b0 <- read8 rbuf
    let flag = b0 .>>. 6
        b1 = fromIntegral (b0 .&. 0b00111111)
    case flag of
      0 -> return b1
      1 -> loop b1 1
      2 -> loop b1 3
      _ -> loop b1 7
  where
    loop :: Int64 -> Int -> IO Int64
    loop r 0 = return r
    loop r n = do
        b <- fromIntegral <$> read8 rbuf
        loop (r*256 + b) (n - 1)
