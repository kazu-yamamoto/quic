{-# LANGUAGE DeriveGeneric #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Network.QUIC.Packet.Token (
    CryptoToken (..),
    isRetryToken,
    generateToken,
    generateRetryToken,
    encryptToken,
    decryptToken,
) where

import Codec.Serialise
import qualified Crypto.Token as CT
import qualified Data.ByteString.Lazy as BL
import Data.UnixTime
import GHC.Generics

import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

data CryptoToken = CryptoToken
    { tokenQUICVersion :: Version
    , tokenLifeTime :: Word32
    , tokenCreatedTime :: TimeMicrosecond
    , tokenCIDs :: Maybe (CID, CID, CID) -- local, remote, orig local
    }
    deriving (Generic)

instance Serialise UnixTime
instance Serialise Version
instance Serialise CID
instance Serialise CryptoToken

isRetryToken :: CryptoToken -> Bool
isRetryToken token = isJust $ tokenCIDs token

----------------------------------------------------------------

generateToken :: Version -> Int -> IO CryptoToken
generateToken ver life = do
    t <- getTimeMicrosecond
    return $ CryptoToken ver (fromIntegral life) t Nothing

generateRetryToken :: Version -> Int -> CID -> CID -> CID -> IO CryptoToken
generateRetryToken ver life l r o = do
    t <- getTimeMicrosecond
    return $ CryptoToken ver (fromIntegral life) t $ Just (l, r, o)

----------------------------------------------------------------

encryptToken :: CT.TokenManager -> CryptoToken -> IO Token
encryptToken mgr ct = CT.encryptToken mgr (encodeCryptoToken ct)

decryptToken :: CT.TokenManager -> Token -> IO (Maybe CryptoToken)
decryptToken mgr token =
    (>>= decodeCryptoToken) <$> CT.decryptToken mgr token

----------------------------------------------------------------

encodeCryptoToken :: CryptoToken -> Token
encodeCryptoToken = BL.toStrict . serialise

decodeCryptoToken :: Token -> Maybe CryptoToken
decodeCryptoToken token = case deserialiseOrFail (BL.fromStrict token) of
    Left DeserialiseFailure{} -> Nothing
    Right x -> Just x
