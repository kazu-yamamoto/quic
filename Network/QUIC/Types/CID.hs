module Network.QUIC.Types.CID (
    CID(..)
  , myCIDLength
  , newCID
  , fromCID
  , toCID
  , makeCID
  , unpackCID
  , OrigCID(..)
  , originalCID
  ) where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString.Short as Short

import Network.QUIC.Imports

myCIDLength :: Int
myCIDLength = 8

-- A type for conneciton ID.
newtype CID = CID Bytes deriving (Eq, Ord)

instance Show CID where
    show (CID cid) = "CID=" ++ shortToString (enc16s cid)

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

data OrigCID = OCFirst CID | OCRetry CID deriving (Eq, Show)

originalCID :: OrigCID -> CID
originalCID (OCFirst cid) = cid
originalCID (OCRetry cid) = cid

