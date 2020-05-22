module Network.QUIC.Types.CID (
    CID(..)
  , myCIDLength
  , newCID
  , fromCID
  , toCID
  , makeCID
  , unpackCID
  , StatelessResetToken(..)
  , newStatelessResetToken
  , PathData(..)
  , newPathData
  , CIDInfo(..)
  ) where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString.Short as Short

import Network.QUIC.Imports

myCIDLength :: Int
myCIDLength = 8

-- A type for conneciton ID.
newtype CID = CID Bytes deriving (Eq, Ord)

instance Show CID where
    show (CID cid) = shortToString (enc16s cid)

newCID :: IO CID
newCID = toCID <$> getRandomBytes myCIDLength

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
newtype StatelessResetToken = StatelessResetToken Bytes deriving (Eq,Ord,Show)

newStatelessResetToken :: IO StatelessResetToken
newStatelessResetToken = StatelessResetToken . Short.toShort <$> getRandomBytes 16

-- 8 bytes
newtype PathData = PathData Bytes deriving (Eq,Show)

newPathData :: IO PathData
newPathData = PathData . Short.toShort <$> getRandomBytes 8

data CIDInfo = CIDInfo {
    cidInfoSeq :: Int
  , cidInfoCID :: CID
  , cidInfoSRT :: StatelessResetToken
  } deriving (Eq, Ord, Show)
