{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Packet.Token (
    CryptoToken (..),
    isRetryToken,
    isTokenAddress,
    generateToken,
    generateRetryToken,
    encryptToken,
    decryptToken,
) where

import qualified Crypto.Token as CT
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as Short
import Data.UnixTime
import Foreign.C.Types (CTime (..))
import Network.Socket (
    SockAddr (..),
    hostAddress6ToTuple,
    hostAddressToTuple,
 )

import Network.QUIC.Codec
import Network.QUIC.Imports hiding (word8)
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

-- | The address alone, without the port: four octets for IPv4 and sixteen
--   for IPv6.
--
-- A NAT hands a client a new port whenever it pleases, and it is the address
-- RFC 9000 Sec 8.1.3 asks about.  The token goes back and forth in Initial
-- packets, so it is written as the octets rather than as the text of the
-- address, which runs to thirty-nine characters for an IPv6 one.
addressForToken :: SockAddr -> ByteString
addressForToken (SockAddrInet _ ha) = BS.pack [a, b, c, d]
  where
    (a, b, c, d) = hostAddressToTuple ha
addressForToken (SockAddrInet6 _ _ ha6 _) = BS.pack $ concatMap octets [a, b, c, d, e, f, g, h]
  where
    (a, b, c, d, e, f, g, h) = hostAddress6ToTuple ha6
    octets w = [fromIntegral (w `shiftR` 8), fromIntegral w]
addressForToken _ = BS.empty

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

-- Read back only by the server that wrote it, after decryption: a token
-- of another release fails to decode and is taken for none.
encodeCryptoToken :: CryptoToken -> Token
encodeCryptoToken CryptoToken{..} =
    runBuilder $
        word8 tokenFormat
            <> word32BE ver
            <> word32BE tokenLifeTime
            <> int64BE (fromIntegral secs)
            <> word32BE (fromIntegral $ utMicroSeconds tokenCreatedTime)
            <> maybe (word8 0) cids tokenCIDs
            <> opaque8 tokenAddress
  where
    Version ver = tokenQUICVersion
    CTime secs = utSeconds tokenCreatedTime
    cids (l, r, o) = word8 1 <> cid l <> cid r <> cid o
    cid (CID c) = opaque8 $ Short.fromShort c

decodeCryptoToken :: Token -> Maybe CryptoToken
decodeCryptoToken = runParser $ do
    fmt <- getWord8
    when (fmt /= tokenFormat) $ fail "unknown format"
    ver <- Version <$> getWord32
    life <- getWord32
    secs <- getInt64
    usecs <- getWord32
    mcids <-
        getWord8 >>= \b -> case b of
            0 -> return Nothing
            1 -> (\l r o -> Just (l, r, o)) <$> cid <*> cid <*> cid
            _ -> fail "bad CIDs"
    addr <- getOpaque8
    let created = UnixTime (CTime $ fromIntegral secs) (fromIntegral usecs)
    return $ CryptoToken ver life created mcids addr
  where
    cid = CID . Short.toShort <$> getOpaque8

tokenFormat :: Word8
tokenFormat = 1
