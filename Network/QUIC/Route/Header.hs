module Network.QUIC.Route.Header where

import Network.QUIC.Imports
import Network.QUIC.Transport
import Network.QUIC.Types

data PlainHeader = PHVersionNegotiation CID CID
                 | PHInitial   Version  CID CID Token
                 | PHRTT0      Version  CID CID
                 | PHHandshake Version  CID CID
                 | PHRetry     Version  CID CID CID Token
                 | PHShort              CID
                 deriving (Eq, Show)

decodePlainHeader :: ByteString -> IO PlainHeader
decodePlainHeader bin = withReadBuffer bin $ \rbuf -> do
    proFlags <- read8 rbuf
    if isLong proFlags then do
        version <- decodeVersion <$> read32 rbuf
        dCIDlen <- fromIntegral <$> read8 rbuf
        dCID <- makeCID <$> extractShortByteString rbuf dCIDlen
        sCIDlen <- fromIntegral <$> read8 rbuf
        sCID <- makeCID <$> extractShortByteString rbuf sCIDlen
        case version of
          Negotiation -> return $ PHVersionNegotiation dCID sCID
          _           -> case decodeLongHeaderPacketType proFlags of
            Initial   -> do
                tokenLen <- fromIntegral <$> decodeInt' rbuf
                token <- extractByteString rbuf tokenLen
                return $ PHInitial version dCID sCID token
            RTT0      -> return $ PHRTT0 version dCID sCID
            Handshake -> return $ PHHandshake version dCID sCID
            Retry     -> do
                odCIDlen <- fromIntegral <$> read8 rbuf
                odCID <- makeCID <$> extractShortByteString rbuf odCIDlen
                tokenLen <- fromIntegral <$> decodeInt' rbuf
                token <- extractByteString rbuf tokenLen
                return $ PHRetry version dCID sCID odCID token
      else
        PHShort . makeCID <$> extractShortByteString rbuf myCIDLength
