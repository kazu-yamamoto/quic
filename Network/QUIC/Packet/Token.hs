{-# LANGUAGE DeriveGeneric #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Network.QUIC.Packet.Token (
    CryptoToken (..),
    isRetryToken,
    isTokenAddress,
    generateToken,
    generateRetryToken,
    encryptToken,
    decryptToken,
) where

import Codec.Serialise
import qualified Crypto.Token as CT
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as BL
import Data.IP (fromSockAddr)
import Data.UnixTime
import GHC.Generics
import Network.Socket (SockAddr)

import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

data CryptoToken = CryptoToken
    { tokenQUICVersion :: Version
    , tokenLifeTime :: Word32
    , tokenCreatedTime :: TimeMicrosecond
    , tokenCIDs :: Maybe (CID, CID, CID) -- local, remote, orig local
    , tokenAddress :: ByteString
    -- ^ The address the token was issued to, as 'addressForToken' writes it
    }
    deriving (Generic)

instance Serialise UnixTime
instance Serialise CryptoToken

isRetryToken :: CryptoToken -> Bool
isRetryToken token = isJust $ tokenCIDs token

-- | Whether the token was issued to this address.
--
-- RFC 9000 Sec 8.1.3: "Tokens sent in NEW_TOKEN frames MUST include
-- information that allows the server to verify that the client IP address
-- has not changed from when the token was issued."  Without it, whoever
-- holds a token can have the server treat any address as validated, and the
-- three-times anti-amplification limit is off for an address that has proved
-- nothing -- the same hole #114 closed for a token the server cannot read at
-- all, left open for one it can.
isTokenAddress :: CryptoToken -> SockAddr -> Bool
isTokenAddress token sa = tokenAddress token == addressForToken sa

-- | The address alone, without the port.  A NAT hands a client a new port
--   whenever it pleases, and it is the address RFC 9000 Sec 8.1.3 asks about.
addressForToken :: SockAddr -> ByteString
addressForToken sa = case fromSockAddr sa of
    Just (ip, _) -> C8.pack $ show ip
    Nothing -> C8.empty

----------------------------------------------------------------

generateToken :: Version -> Int -> SockAddr -> IO CryptoToken
generateToken ver life sa = do
    t <- getTimeMicrosecond
    return $ CryptoToken ver (fromIntegral life) t Nothing $ addressForToken sa

generateRetryToken
    :: Version -> Int -> CID -> CID -> CID -> SockAddr -> IO CryptoToken
generateRetryToken ver life l r o sa = do
    t <- getTimeMicrosecond
    return $
        CryptoToken ver (fromIntegral life) t (Just (l, r, o)) $
            addressForToken sa

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
