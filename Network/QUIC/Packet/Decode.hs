{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Packet.Decode (
    decodePacket
  , decodePackets
  , decodeCryptPackets
  , decodeStatelessResetToken
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Short as Short

import Network.QUIC.Exception
import Network.QUIC.Imports
import Network.QUIC.Logger
import Network.QUIC.Packet.Header
import Network.QUIC.Packet.Version
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

decodeCryptPackets :: ByteString -> IO [(CryptPacket,EncryptionLevel)]
decodeCryptPackets bs0 = unwrap <$> decodePackets bs0
  where
    unwrap (PacketIC c l:xs) = (c,l) : unwrap xs
    unwrap (_:xs)            = unwrap xs
    unwrap []                = []

-- Client uses this.
decodePackets :: ByteString -> IO [PacketI]
decodePackets bs0 = loop bs0 id
  where
    loop "" build = return $ build [] -- fixme
    loop bs build = do
        (pkt, rest) <- decodePacket bs
        loop rest (build . (pkt :))

-- Server uses this.
decodePacket :: ByteString -> IO (PacketI, ByteString)
decodePacket bs = handleLogR logAction $ withReadBuffer bs $ \rbuf -> do
    save rbuf
    proFlags <- Flags <$> read8 rbuf
    let short = isShort proFlags
    pkt <- decode rbuf proFlags short
    siz <- savingSize rbuf
    let rest = B.drop siz bs
    return (pkt, rest)
  where
    logAction msg = do
        stdoutLogger ("decodePacket: " <> msg)
        return (PacketIB BrokenPacket,"")
    decode rbuf _proFlags True = do
        header <- Short . makeCID <$> extractShortByteString rbuf myCIDLength
        cpkt <- CryptPacket header <$> makeShortCrypt bs rbuf
        return $ PacketIC cpkt RTT1Level
    decode rbuf proFlags False = do
        (ver, dCID, sCID) <- decodeLongHeader rbuf
        case ver of
          Negotiation      -> do
              decodeVersionNegotiationPacket rbuf dCID sCID
          _                -> case decodeLongHeaderPacketType proFlags of
            RetryPacketType     -> do
                decodeRetryPacket rbuf proFlags ver dCID sCID
            RTT0PacketType      -> do
                let header = RTT0 ver dCID sCID
                cpkt <- CryptPacket header <$> makeLongCrypt bs rbuf
                return $ PacketIC cpkt RTT0Level
            InitialPacketType   -> do
                tokenLen <- fromIntegral <$> decodeInt' rbuf
                token <- extractByteString rbuf tokenLen
                let header = Initial ver dCID sCID token
                cpkt <- CryptPacket header <$> makeLongCrypt bs rbuf
                return $ PacketIC cpkt InitialLevel
            HandshakePacketType -> do
                let header = Handshake ver dCID sCID
                crypt <- CryptPacket header <$> makeLongCrypt bs rbuf
                return $ PacketIC crypt HandshakeLevel

makeShortCrypt :: ByteString -> ReadBuffer -> IO Crypt
makeShortCrypt bs rbuf = do
    len <- remainingSize rbuf
    here <- savingSize rbuf
    ff rbuf len
    return $ Crypt here bs 0

makeLongCrypt :: ByteString -> ReadBuffer -> IO Crypt
makeLongCrypt bs rbuf = do
    len <- fromIntegral <$> decodeInt' rbuf
    here <- savingSize rbuf
    ff rbuf len
    let pkt = B.take (here + len) bs
    return $ Crypt here pkt 0

----------------------------------------------------------------

decodeLongHeader :: ReadBuffer -> IO (Version, CID, CID)
decodeLongHeader rbuf  = do
    ver     <- decodeVersion <$> read32 rbuf
    dcidlen <- fromIntegral <$> read8 rbuf
    dCID    <- makeCID <$> extractShortByteString rbuf dcidlen
    scidlen <- fromIntegral <$> read8 rbuf
    sCID    <- makeCID <$> extractShortByteString rbuf scidlen
    return (ver, dCID, sCID)

decodeVersionNegotiationPacket :: ReadBuffer -> CID -> CID -> IO PacketI
decodeVersionNegotiationPacket rbuf dCID sCID = do
    siz <- remainingSize rbuf
    vers <- decodeVersions siz id
    return $ PacketIV $ VersionNegotiationPacket dCID sCID vers
  where
    decodeVersions siz vers
      | siz >= 4  = do
            ver <- decodeVersion <$> read32 rbuf
            decodeVersions (siz - 4) ((ver :) . vers)
      | otherwise = return $ vers []

decodeRetryPacket :: ReadBuffer -> Flags Protected -> Version -> CID -> CID -> IO PacketI
decodeRetryPacket rbuf _proFlags version dCID sCID = do
    rsiz <- remainingSize rbuf
    token <- extractByteString rbuf (rsiz - 16)
    siz <- savingSize rbuf
    pseudo <- extractByteString rbuf $ negate siz
    tag <- extractByteString rbuf 16
    return $ PacketIR $ RetryPacket version dCID sCID token (Right (pseudo,tag))

----------------------------------------------------------------

decodeStatelessResetToken :: ByteString -> Maybe StatelessResetToken
decodeStatelessResetToken bs
  | len < 21  = Nothing
  | otherwise = Just $ StatelessResetToken $ Short.toShort token
  where
    len = B.length bs
    (_,token) = B.splitAt (len - 16) bs
