{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC.Transport.Header where

import qualified Data.ByteString as B

import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Types

isLong :: Word8 -> Bool
isLong flags = testBit flags 7

analyzeLongHeaderPacket :: ByteString -> IO (Maybe (CID, CID))
analyzeLongHeaderPacket bin = withReadBuffer bin $ \rbuf -> do
    proFlags <- read8 rbuf
    if isLong proFlags then do
        _ <- read32 rbuf
        dcIDlen <- fromIntegral <$> read8 rbuf
        dcID <- makeCID <$> extractShortByteString rbuf dcIDlen
        scIDlen <- fromIntegral <$> read8 rbuf
        scID <- makeCID <$> extractShortByteString rbuf scIDlen
        return $ Just (dcID, scID)
      else
        return Nothing

----------------------------------------------------------------

encodeLongHeaderPacketType :: RawFlags -> LongHeaderPacketType -> RawFlags
encodeLongHeaderPacketType flags LHInitial   = flags .|. 0b11000000
encodeLongHeaderPacketType flags LHRTT0      = flags .|. 0b11010000
encodeLongHeaderPacketType flags LHHandshake = flags .|. 0b11100000
encodeLongHeaderPacketType flags LHRetry     = flags .|. 0b11110000

decodeLongHeaderPacketType :: RawFlags -> LongHeaderPacketType
decodeLongHeaderPacketType flags = case flags .&. 0b00110000 of
    0b00000000 -> LHInitial
    0b00010000 -> LHRTT0
    0b00100000 -> LHHandshake
    _          -> LHRetry

----------------------------------------------------------------

packetEncryptionLevel :: ByteString -> EncryptionLevel
packetEncryptionLevel bs
  | isLong w  = case decodeLongHeaderPacketType w of
                  LHInitial   -> InitialLevel
                  LHRetry     -> InitialLevel
                  LHHandshake -> HandshakeLevel
                  _           -> undefined
  | otherwise     = RTT1Level
  where
    w = B.head bs
