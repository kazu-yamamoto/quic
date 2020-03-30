{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Types.Packet where

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.CID
import Network.QUIC.Types.Frame

----------------------------------------------------------------

-- | QUIC version.
data Version = Negotiation
             | UnknownVersion Word32
             | Draft18
             | Draft19
             | Draft20
             | Draft21
             | Draft22
             | Draft23
             | Draft24
             | Draft25
             | Draft26
             | Draft27
             | GreasingVersion
             deriving (Eq, Ord, Show)

----------------------------------------------------------------

data PacketI = PacketIV VersionNegotiationPacket
             | PacketIR RetryPacket
             | PacketIC CryptPacket
             | PacketIB BrokenPacket
             deriving (Eq, Show)

-- Not used internally. Only for 'encodePacket'.
data PacketO = PacketOV VersionNegotiationPacket
             | PacketOR RetryPacket
             | PacketOP PlainPacket
             deriving (Eq, Show)

data VersionNegotiationPacket = VersionNegotiationPacket CID CID [Version]
                              deriving (Eq, Show)

data RetryPacket = RetryPacket Version CID CID Token (Either CID (ByteString,ByteString))
                 deriving (Eq, Show)

data BrokenPacket = BrokenPacket deriving (Eq, Show)

data Header = Initial   Version  CID CID Token
            | RTT0      Version  CID CID
            | Handshake Version  CID CID
            | Short              CID
            deriving (Eq, Show)

headerMyCID :: Header -> CID
headerMyCID (Initial   _ cid _ _) = cid
headerMyCID (RTT0      _ cid _)   = cid
headerMyCID (Handshake _ cid _)   = cid
headerMyCID (Short       cid)     = cid

headerPeerCID :: Header -> CID
headerPeerCID (Initial   _ _ cid _) = cid
headerPeerCID (RTT0      _ _ cid)   = cid
headerPeerCID (Handshake _ _ cid)   = cid
headerPeerCID  Short{}              = CID ""

data PlainPacket = PlainPacket Header Plain deriving (Eq, Show)
data CryptPacket = CryptPacket Header Crypt deriving (Eq, Show)

data Plain  = Plain  {
    plainFlags        :: Flags Raw
  , plainPacketNumber :: PacketNumber
  , plainFrames       :: [Frame]
  } deriving (Eq, Show)

data Crypt = Crypt {
    cryptPktNumOffset :: Int
  , cryptPacket       :: ByteString
  , cryptFlags        :: Int
  } deriving (Eq, Show)

isCryptLogged :: Crypt -> Bool
isCryptLogged  crypt = cryptFlags crypt `testBit` 0

isCryptDelayed :: Crypt -> Bool
isCryptDelayed crypt = cryptFlags crypt `testBit` 1

setCryptLogged :: Crypt -> Crypt
setCryptLogged  crypt = crypt { cryptFlags = cryptFlags crypt `setBit` 0 }

setCryptDelayed :: Crypt -> Crypt
setCryptDelayed crypt = crypt { cryptFlags = cryptFlags crypt `setBit` 1 }

data StatelessReset = StatelessReset deriving (Eq, Show)

----------------------------------------------------------------

data LongHeaderPacketType = InitialPacketType
                          | RTT0PacketType
                          | HandshakePacketType
                          | RetryPacketType
                          deriving (Eq, Show)

data EncryptionLevel = InitialLevel
                     | RTT0Level
                     | HandshakeLevel
                     | RTT1Level
                     deriving (Eq, Ord, Show)

packetEncryptionLevel :: Header -> EncryptionLevel
packetEncryptionLevel Initial{}   = InitialLevel
packetEncryptionLevel RTT0{}      = RTT0Level
packetEncryptionLevel Handshake{} = HandshakeLevel
packetEncryptionLevel Short{}     = RTT1Level

----------------------------------------------------------------

newtype Flags a = Flags Word8 deriving (Eq, Show)

data Protected
data Raw

----------------------------------------------------------------

type EncodedPacketNumber = Word32
