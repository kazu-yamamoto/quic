{-# LANGUAGE DeriveGeneric #-}

module Network.QUIC.Types.CID (
    CID (..),
    myCIDLength,
    newCID,
    fromCID,
    toCID,
    makeCID,
    unpackCID,
    StatelessResetToken (..),
    newStatelessResetToken,
    PathData (..),
    newPathData,
    CIDInfo,
    newCIDInfo,
    cidInfoSeq,
    cidInfoCID,
    cidInfoSRT,
) where

import qualified Data.ByteString.Short as Short

import Codec.Serialise
import GHC.Generics

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

-- 16 bytes
newtype StatelessResetToken = StatelessResetToken Bytes deriving (Eq, Ord, Show)

newStatelessResetToken :: IO StatelessResetToken
newStatelessResetToken = StatelessResetToken <$> getRandomBytes 16

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
