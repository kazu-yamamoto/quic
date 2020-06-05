module Network.QUIC.Packet.Token (
    CryptoToken(..)
  , isRetryToken
  , generateToken
  , generateRetryToken
  , encryptToken
  , decryptToken
  ) where

import qualified Crypto.Token as CT
import Foreign.Storable
import Foreign.Ptr
import Network.ByteOrder

import Network.QUIC.Imports
import Network.QUIC.Packet.Version
import Network.QUIC.TLS
import Network.QUIC.Time
import Network.QUIC.Types

----------------------------------------------------------------

data CryptoToken = CryptoToken {
    tokenQUICVersion :: Version
  , tokenCreatedTime :: Elapsed
  , tokenCIDs        :: Maybe (CID, CID, CID) -- local, remote, orig local
  }

isRetryToken :: CryptoToken -> Bool
isRetryToken token = isJust $ tokenCIDs token

----------------------------------------------------------------

generateToken :: Version -> IO CryptoToken
generateToken ver = do
    t <- timeCurrent
    return $ CryptoToken ver t Nothing

generateRetryToken :: Version -> CID -> CID -> CID -> IO CryptoToken
generateRetryToken ver l r o = do
    t <- timeCurrent
    return $ CryptoToken ver t $ Just (l,r,o)

----------------------------------------------------------------

encryptToken :: CT.TokenManager -> CryptoToken -> IO Token
encryptToken = CT.encryptToken

decryptToken :: CT.TokenManager -> Token -> IO (Maybe CryptoToken)
decryptToken = CT.decryptToken

----------------------------------------------------------------

-- length includes its field
instance Storable CryptoToken where
    sizeOf (CryptoToken _ _ Nothing) = 1 + 4 + 8 + 1
    sizeOf (CryptoToken _ _ (Just (l,r,o))) =
        let (_, llen) = unpackCID l
            (_, rlen) = unpackCID r
            (_, olen) = unpackCID o
        in 1 + 4 + 8 + 1 + 3 + fromIntegral (llen + rlen + olen)
    alignment _ = 4
    peek ptr = do
        len0 <- peek (castPtr ptr :: Ptr Word8)
        let len = fromIntegral len0 - 1
        rbuf <- newReadBuffer (castPtr (ptr `plusPtr` 1)) len
        ver  <- decodeVersion <$> read32 rbuf
        tim  <- Elapsed . Seconds . fromIntegral <$> read64 rbuf
        typ <- read8 rbuf
        case typ of
          0 -> return $ CryptoToken ver tim Nothing
          _ -> do
              llen <- fromIntegral <$> read8 rbuf
              lCID <- makeCID <$> extractShortByteString rbuf llen
              rlen <- fromIntegral <$> read8 rbuf
              rCID <- makeCID <$> extractShortByteString rbuf rlen
              olen <- fromIntegral <$> read8 rbuf
              oCID <- makeCID <$> extractShortByteString rbuf olen
              return $ CryptoToken ver tim $ Just (lCID, rCID, oCID)
    poke ptr rt@(CryptoToken ver tim mcids) = do
        let len = sizeOf rt
        wbuf <- newWriteBuffer (castPtr ptr) len
        write8 wbuf $ fromIntegral len
        write32 wbuf $ encodeVersion ver
        let Elapsed (Seconds t) = tim
        write64 wbuf $ fromIntegral t
        case mcids of
          Nothing      -> write8 wbuf 0
          Just (l,r,o) -> do
              write8 wbuf 1
              let (lcid, llen) = unpackCID l
              write8 wbuf llen
              copyShortByteString wbuf lcid
              let (rcid, rlen) = unpackCID r
              write8 wbuf rlen
              copyShortByteString wbuf rcid
              let (ocid, olen) = unpackCID o
              write8 wbuf olen
              copyShortByteString wbuf ocid
