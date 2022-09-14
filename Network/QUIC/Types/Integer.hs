{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC.Types.Integer (
    encodeInt
  , encodeInt8
  , encodeInt'
  , encodeInt'2
  , encodeInt'4
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
encodeInt i = unsafeCreate n $ go tag n i'
  where
    (tag,n,i') = tagLen i
{-# NOINLINE encodeInt #-}

encodeInt8 :: Int64  -> ByteString
encodeInt8 i = unsafeCreate n $ go tag n i
  where
    n = 8
    tag = 0b11000000
{-# NOINLINE encodeInt8 #-}

encodeInt' :: WriteBuffer -> Int64 -> IO ()
encodeInt' wbuf i = go' tag n i' wbuf
  where
    (tag,n,i') = tagLen i

encodeInt'2 :: WriteBuffer -> Int64 -> IO ()
encodeInt'2 wbuf i = go' tag n i' wbuf
  where
    tag = 0b01000000
    n = 2
    i' = i !<<. 48

encodeInt'4 :: WriteBuffer -> Int64 -> IO ()
encodeInt'4 wbuf i = go' tag n i' wbuf
  where
    tag = 0b10000000
    n = 4
    i' = i !<<. 32

tagLen :: Int64 -> (Word8, Int, Int64)
tagLen i | i <=         63 = (0b00000000, 1, i !<<. 56)
         | i <=      16383 = (0b01000000, 2, i !<<. 48)
         | i <= 1073741823 = (0b10000000, 4, i !<<. 32)
         | otherwise       = (0b11000000, 8, i)
{-# INLINE tagLen #-}

msb8 :: Int64 -> Word8
msb8 i = fromIntegral (i !>>. 56)
{-# INLINE msb8 #-}

go :: Word8 -> Int -> Int64 -> Ptr Word8 -> IO ()
go tag n0 i0 p0 = do
    poke p0 (tag .|. msb8 i0)
    let n' = n0 - 1
        i' = i0 !<<. 8
        p' = p0 `plusPtr` 1
    loop n' i' p'
  where
    loop 0 _ _ = return ()
    loop n i p = do
        poke p $ msb8 i
        let n' = n - 1
            i' = i !<<. 8
            p' = p `plusPtr` 1
        loop n' i' p'
{-# INLINE go #-}

go' :: Word8 -> Int -> Int64 -> WriteBuffer -> IO ()
go' tag n0 i0 wbuf = do
    write8 wbuf (tag .|. msb8 i0)
    let n' = n0 - 1
        i' = i0 !<<. 8
    loop n' i'
  where
    loop 0 _ = return ()
    loop n i = do
        write8 wbuf $ msb8 i
        let n' = n - 1
            i' = i !<<. 8
        loop n' i'
{-# INLINE go' #-}

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
    let flag = b0 !>>. 6
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
