module Network.QUIC.Packet.Token (
    RetryToken(..)
  , encryptRetryToken
  , decryptRetryToken
  ) where

import Crypto.Token
import Foreign.Storable
import Foreign.Ptr
import Network.ByteOrder

import Network.QUIC.Packet.Version
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

data RetryToken = RetryToken {
    tokenVersion :: Version
  , localCID     :: CID
  , remoteCID    :: CID
  , origLocalCID :: CID
  }

encryptRetryToken :: TokenManager -> RetryToken -> IO ByteString
encryptRetryToken = encryptToken

decryptRetryToken :: TokenManager -> ByteString -> IO (Maybe RetryToken)
decryptRetryToken = decryptToken

----------------------------------------------------------------

instance Storable RetryToken where
    sizeOf (RetryToken _ver lCID rCID oCID) =
        let (_, llen) = unpackCID lCID
            (_, rlen) = unpackCID rCID
            (_, olen) = unpackCID oCID
        in 7 + fromIntegral (llen + rlen + olen)
    alignment _ = 4
    peek ptr = do
        rbuf <- newReadBuffer (castPtr ptr) 1024 -- fixme
        ver  <- decodeVersion <$> read32 rbuf
        llen <- fromIntegral <$> read8 rbuf
        lCID <- makeCID <$> extractShortByteString rbuf llen
        rlen <- fromIntegral <$> read8 rbuf
        rCID <- makeCID <$> extractShortByteString rbuf rlen
        olen <- fromIntegral <$> read8 rbuf
        oCID <- makeCID <$> extractShortByteString rbuf olen
        return $ RetryToken ver lCID rCID oCID
    poke ptr rt@(RetryToken ver lCID rCID oCID) = do
        wbuf <- newWriteBuffer (castPtr ptr) (sizeOf rt)
        write32 wbuf $ encodeVersion ver
        let (lcid, llen) = unpackCID lCID
        write8 wbuf llen
        copyShortByteString wbuf lcid
        let (rcid, rlen) = unpackCID rCID
        write8 wbuf rlen
        copyShortByteString wbuf rcid
        let (ocid, olen) = unpackCID oCID
        write8 wbuf olen
        copyShortByteString wbuf ocid
