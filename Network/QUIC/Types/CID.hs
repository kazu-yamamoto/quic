{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Types.CID (
    CID (..),
    myCIDLength,
    newCID,
    fromCID,
    toCID,
    makeCID,
    unpackCID,
    nonZeroLengthCID,
    StatelessResetToken (..),
    fromStatelessResetToken,
    makeGenStatelessReset,
    PathData (..),
    newPathData,
    CIDInfo,
    newCIDInfo,
    cidInfoSeq,
    cidInfoCID,
    cidInfoSRT,
) where

import Codec.Serialise
import Crypto.Hash
import Crypto.KDF.HKDF
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as Short
import GHC.Generics
import Network.Socket (SockAddr)
#if MIN_VERSION_random(1,3,0)
import System.Random (getStdRandom, uniformByteString)
#else
import System.Random (getStdRandom, genByteString)
#endif

import Network.QUIC.Imports

myCIDLength :: Int
myCIDLength = 8

-- | A type for conneciton ID.
newtype CID = CID Bytes deriving (Eq, Ord, Generic)

instance Serialise CID

instance Show CID where
    show (CID cid) = shortToString (enc16s cid)

newCID :: IO CID
newCID = CID <$> getRandomBytes myCIDLength

toCID :: ByteString -> CID
toCID = CID . Short.toShort

-- | Converting a connection ID.
fromCID :: CID -> ByteString
fromCID (CID sbs) = Short.fromShort sbs

makeCID :: ShortByteString -> CID
makeCID = CID

unpackCID :: CID -> (ShortByteString, Word8)
unpackCID (CID sbs) = (sbs, len)
  where
    len = fromIntegral $ Short.length sbs

nonZeroLengthCID :: CID -> SockAddr -> CID
nonZeroLengthCID (CID "") sa = toCID $ C8.pack $ show sa
nonZeroLengthCID x _ = x

-- 16 bytes
newtype StatelessResetToken = StatelessResetToken Bytes deriving (Eq, Ord)

instance Show StatelessResetToken where
    show (StatelessResetToken srt) = shortToString (enc16s srt)

fromStatelessResetToken :: StatelessResetToken -> ByteString
fromStatelessResetToken (StatelessResetToken srt) = Short.fromShort srt

makeGenStatelessReset :: IO (CID -> StatelessResetToken)
makeGenStatelessReset = do
#if MIN_VERSION_random(1,3,0)
    salt <- getStdRandom $ uniformByteString 20
    ikm <- getStdRandom $ uniformByteString 20
#else
    salt <- getStdRandom $ genByteString 20
    ikm <- getStdRandom $ genByteString 20
#endif
    let prk = extract salt ikm :: PRK SHA256
        makeStatelessReset dcid = StatelessResetToken $ Short.toShort $ expand prk (fromCID dcid) 16
    return makeStatelessReset

-- 8 bytes
newtype PathData = PathData Bytes deriving (Eq, Show)

newPathData :: IO PathData
newPathData = PathData <$> getRandomBytes 8

data CIDInfo = CIDInfo
    { cidInfoSeq :: Int
    , cidInfoCID :: CID
    , cidInfoSRT :: StatelessResetToken
    }
    deriving (Eq, Ord, Show)

newCIDInfo :: Int -> CID -> StatelessResetToken -> CIDInfo
newCIDInfo n cid srt =
    CIDInfo
        { cidInfoSeq = n
        , cidInfoCID = cid
        , cidInfoSRT = srt
        }
