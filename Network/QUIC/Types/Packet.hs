{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Types.Packet where

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.CID
import Network.QUIC.Types.Frame

----------------------------------------------------------------

data Version = Negotiation
             | Draft18
             | Draft19
             | Draft20
             | Draft21
             | Draft22
             | Draft23
             | Draft24
             | UnknownVersion Word32
             deriving (Eq, Show)

currentDraft :: Version
currentDraft = Draft24

----------------------------------------------------------------

data PacketI = PacketIV VersionNegotiationPacket
             | PacketIR RetryPacket
             | PacketIC CryptPacket
             deriving (Eq, Show)

-- Not used internally. Only for 'encodePacket'.
data PacketO = PacketOV VersionNegotiationPacket
             | PacketOR RetryPacket
             | PacketOP PlainPacket
             deriving (Eq, Show)

data VersionNegotiationPacket = VersionNegotiationPacket CID CID [Version]
                              deriving (Eq, Show)

data RetryPacket = RetryPacket Version CID CID CID Token deriving (Eq, Show)

data Header = Initial   Version  CID CID Token
            | RTT0      Version  CID CID
            | Handshake Version  CID CID
            | Short              CID
            deriving (Eq, Show)

headerPeerCID :: Header -> CID
headerPeerCID (Initial   _ _ cid _) = cid
headerPeerCID (RTT0      _ _ cid)   = cid
headerPeerCID (Handshake _ _ cid)   = cid
headerPeerCID  Short{}              = CID ""

data PlainPacket = PlainPacket Header Plain deriving (Eq, Show)
data CryptPacket = CryptPacket Header Crypt deriving (Eq, Show)

data Plain  = Plain  {
    plainFlags        :: RawFlags
  , plainPacketNumber :: PacketNumber
  , plainFrames       :: [Frame]
  } deriving (Eq, Show)

data Crypt = Crypt {
    cryptPktNumOffset :: Int
  , cryptPacket       :: ByteString
  } deriving (Eq, Show)

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

type EncodedPacketNumber = Word32
type RawFlags = Word8
