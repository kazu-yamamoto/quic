-- | A small binary format for what quic stores or hands out: big-endian
--   integers and length-prefixed octets.  Decoding gives 'Nothing' on bad
--   input and never throws.
module Network.QUIC.Codec (
    -- * Encoding
    runBuilder,
    word8,
    word32BE,
    int64BE,
    opaque8,
    opaque32,

    -- * Decoding
    Parser,
    runParser,
    getWord8,
    getWord32,
    getInt64,
    getOpaque8,
    getOpaque32,
) where

import qualified Data.ByteString as BS
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL

import Network.QUIC.Imports hiding (word8)

----------------------------------------------------------------

runBuilder :: Builder -> ByteString
runBuilder = BL.toStrict . toLazyByteString

-- | At most 255 octets.
opaque8 :: ByteString -> Builder
opaque8 bs = word8 (fromIntegral $ BS.length bs) <> byteString bs

opaque32 :: ByteString -> Builder
opaque32 bs = word32BE (fromIntegral $ BS.length bs) <> byteString bs

----------------------------------------------------------------

newtype Parser a = Parser (ByteString -> Maybe (a, ByteString))

instance Functor Parser where
    fmap f (Parser p) = Parser $ \bs -> case p bs of
        Nothing -> Nothing
        Just (x, rest) -> Just (f x, rest)

instance Applicative Parser where
    pure x = Parser $ \bs -> Just (x, bs)
    Parser pf <*> Parser px = Parser $ \bs -> case pf bs of
        Nothing -> Nothing
        Just (f, rest) -> case px rest of
            Nothing -> Nothing
            Just (x, rest') -> Just (f x, rest')

instance Monad Parser where
    Parser p >>= k = Parser $ \bs -> case p bs of
        Nothing -> Nothing
        Just (x, rest) -> let Parser q = k x in q rest

instance MonadFail Parser where
    fail _ = Parser $ const Nothing

-- | The whole input is to be consumed.
runParser :: Parser a -> ByteString -> Maybe a
runParser (Parser p) bs = case p bs of
    Just (x, rest) | BS.null rest -> Just x
    _ -> Nothing

getBytes :: Int -> Parser ByteString
getBytes n = Parser $ \bs ->
    if BS.length bs < n then Nothing else Just (BS.splitAt n bs)

getWord8 :: Parser Word8
getWord8 = BS.head <$> getBytes 1

getWord32 :: Parser Word32
getWord32 = fromIntegral <$> getBE 4

getInt64 :: Parser Int64
getInt64 = fromIntegral <$> getBE 8

getBE :: Int -> Parser Word64
getBE n = BS.foldl' (\acc w -> acc `shiftL` 8 .|. fromIntegral w) 0 <$> getBytes n

getOpaque8 :: Parser ByteString
getOpaque8 = getWord8 >>= getBytes . fromIntegral

getOpaque32 :: Parser ByteString
getOpaque32 = getWord32 >>= getBytes . fromIntegral
