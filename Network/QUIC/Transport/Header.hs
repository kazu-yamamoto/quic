{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC.Transport.Header where

import qualified Data.ByteString as B

import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Transport.Types

isLong :: Word8 -> Bool
isLong flags = testBit flags 7

analyzeLongHeaderPacket :: ByteString -> IO (Maybe (CID, CID))
analyzeLongHeaderPacket bin = withReadBuffer bin $ \rbuf -> do
    proFlags <- read8 rbuf
    if isLong proFlags then do
        _ <- read32 rbuf
        dcIDlen <- fromIntegral <$> read8 rbuf
        dcID <- CID <$> extractShortByteString rbuf dcIDlen
        scIDlen <- fromIntegral <$> read8 rbuf
        scID <- CID <$> extractShortByteString rbuf scIDlen
        return $ Just (dcID, scID)
      else
        return Nothing

----------------------------------------------------------------

encodePacketType :: RawFlags -> LongHeaderPacketType -> RawFlags
encodePacketType flags LHInitial   = flags
encodePacketType flags LHRTT0      = flags .|. 0b00010000
encodePacketType flags LHHandshake = flags .|. 0b00100000
encodePacketType flags LHRetry     = flags .|. 0b00110000

decodePacketType :: RawFlags -> LongHeaderPacketType
decodePacketType flags = case flags .&. 0b00110000 of
    0b00000000 -> LHInitial
    0b00010000 -> LHRTT0
    0b00100000 -> LHHandshake
    _          -> LHRetry

----------------------------------------------------------------

packetEncryptionLevel :: ByteString -> EncryptionLevel
packetEncryptionLevel bs
  | isLong w  = case decodePacketType w of
                  LHInitial   -> InitialLevel
                  LHRetry     -> InitialLevel
                  LHHandshake -> HandshakeLevel
                  _           -> undefined
  | otherwise     = ApplicationLevel
  where
    w = B.head bs
