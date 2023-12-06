module Network.QUIC.Packet.Token (
    CryptoToken (..),
    isRetryToken,
    generateToken,
    generateRetryToken,
    encryptToken,
    decryptToken,
) where

import qualified UnliftIO.Exception as E
import qualified Crypto.Token as CT
import Data.UnixTime
import Foreign.C.Types
import Network.ByteOrder

import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

data CryptoToken = CryptoToken
    { tokenQUICVersion :: Version
    , tokenCreatedTime :: TimeMicrosecond
    , tokenCIDs :: Maybe (CID, CID, CID) -- local, remote, orig local
    }

isRetryToken :: CryptoToken -> Bool
isRetryToken token = isJust $ tokenCIDs token

----------------------------------------------------------------

generateToken :: Version -> IO CryptoToken
generateToken ver = do
    t <- getTimeMicrosecond
    return $ CryptoToken ver t Nothing

generateRetryToken :: Version -> CID -> CID -> CID -> IO CryptoToken
generateRetryToken ver l r o = do
    t <- getTimeMicrosecond
    return $ CryptoToken ver t $ Just (l, r, o)

----------------------------------------------------------------

encryptToken :: CT.TokenManager -> CryptoToken -> IO Token
encryptToken mgr ct = encodeCryptoToken ct >>= CT.encryptToken mgr

decryptToken :: CT.TokenManager -> Token -> IO (Maybe CryptoToken)
decryptToken mgr token = do
    mx <- CT.decryptToken mgr token
    case mx of
      Nothing -> return Nothing
      Just x -> decodeCryptoToken x

----------------------------------------------------------------

cryptoTokenSize :: Int
cryptoTokenSize = 76 -- 4 + 8 + 1 + (1 + 20) * 3

encodeCryptoToken :: CryptoToken -> IO Token
encodeCryptoToken (CryptoToken (Version ver) tim mcids) =
    withWriteBuffer cryptoTokenSize $ \wbuf -> do
        write32 wbuf ver
        let CTime s = utSeconds tim
        write64 wbuf $ fromIntegral s
        case mcids of
            Nothing -> write8 wbuf 0
            Just (l, r, o) -> do
                write8 wbuf 1
                bury wbuf l
                bury wbuf r
                bury wbuf o
      where
        bury wbuf x = do
            let (xcid, xlen) = unpackCID x
            write8 wbuf xlen
            copyShortByteString wbuf xcid
            ff wbuf (20 - fromIntegral xlen)

decodeCryptoToken :: Token -> IO (Maybe CryptoToken)
decodeCryptoToken token = do
    ex <- E.try $ decodeCryptoToken' token
    case ex of
      Left (E.SomeException _) -> return Nothing
      Right x -> return $ Just x

decodeCryptoToken' :: ByteString -> IO CryptoToken
decodeCryptoToken' token = withReadBuffer token $ \rbuf -> do
    ver <- Version <$> read32 rbuf
    s <- CTime . fromIntegral <$> read64 rbuf
    let tim = UnixTime s 0
    typ <- read8 rbuf
    case typ of
        0 -> return $ CryptoToken ver tim Nothing
        _ -> do
            l <- pick rbuf
            r <- pick rbuf
            o <- pick rbuf
            return $ CryptoToken ver tim $ Just (l, r, o)
  where
    pick rbuf = do
        xlen0 <- fromIntegral <$> read8 rbuf
        let xlen = min xlen0 20
        x <- makeCID <$> extractShortByteString rbuf xlen
        ff rbuf (20 - xlen)
        return x
