{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Transport.Integer where

import Data.Bits
import Data.ByteString (ByteString)
import Data.Int (Int64)
import Network.ByteOrder

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Network.QUIC.Utils

----------------------------------------------------------------

-- |
-- >>> enc16 <$> encodeInt 151288809941952652
-- "c2197c5eff14e88c"
-- >>> enc16 <$> encodeInt 494878333
-- "9d7f3e7d"
-- >>> enc16 <$> encodeInt 15293
-- "7bbd"
-- >>> enc16 <$> encodeInt 37
-- "25"
encodeInt :: Int64  -> IO ByteString
encodeInt i = withWriteBuffer 8 $ \wbuf -> encodeInt' wbuf i

encodeInt' :: WriteBuffer -> Int64 -> IO ()
encodeInt' wbuf i
  | i <=         63 = do
        let [w0] = decomp 1 [] i
        write8 wbuf w0
  | i <=      16383 = do
        let [w0,w1] = decomp 2 [] i
        write8 wbuf (w0 .|. 0b01000000)
        write8 wbuf w1
  | i <= 1073741823 = do
        let [w0,w1,w2,w3] = decomp 4 [] i
        write8 wbuf (w0 .|. 0b10000000)
        write8 wbuf w1
        write8 wbuf w2
        write8 wbuf w3
  | otherwise       = do
        let [w0,w1,w2,w3,w4,w5,w6,w7] = decomp 8 [] i
        write8 wbuf (w0 .|. 0b11000000)
        write8 wbuf w1
        write8 wbuf w2
        write8 wbuf w3
        write8 wbuf w4
        write8 wbuf w5
        write8 wbuf w6
        write8 wbuf w7

encodeInt'2 :: WriteBuffer -> Int64 -> IO ()
encodeInt'2 wbuf i = do
    let [w0,w1] = decomp 2 [] i
    write8 wbuf (w0 .|. 0b01000000)
    write8 wbuf w1

decomp :: Int -> [Word8] -> Int64 -> [Word8]
decomp 0 ws _ = ws
decomp n ws x = decomp (n-1) (w:ws) x'
  where
    x' = x `shiftR` 8
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
decodeInt :: ByteString -> IO Int64
decodeInt bs = withReadBuffer bs decodeInt'

decodeInt' :: ReadBuffer -> IO Int64
decodeInt' rbuf = do
    b0 <- read8 rbuf
    let flag = b0 `shiftR` 6
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
