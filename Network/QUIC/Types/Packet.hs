{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Types.Packet where

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.CID
import Network.QUIC.Types.Error

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

data Frame = Padding Int
           | Ping
           | Ack AckInfo Delay
           | RestStream -- fixme
           | StopSending -- fixme
           | Crypto Offset CryptoData
           | NewToken Token
           | Stream StreamID Offset StreamData Fin
           | MaxData -- fixme
           | MaxStreamData -- fixme
           | MaxStreams -- fixme
           | DataBlocked -- fixme
           | StreamDataBlocked -- fixme
           | StreamsBlocked -- fixme
           | NewConnectionID Int Int CID StatelessResetToken
           | RetireConnectionID -- fixme
           | PathChallenge PathData
           | PathResponse PathData
           | ConnectionCloseQUIC TransportError FrameType ReasonPhrase
           | ConnectionCloseApp  TransportError ReasonPhrase
           deriving (Eq,Show)

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

type Length = Int
type StreamID = Int64
type EncodedPacketNumber = Word32
type RawFlags = Word8

type Token = ByteString -- to be decrypted
emptyToken :: Token
emptyToken = ""

type FrameType = Int

type Delay = Int
type CryptoData = ByteString
type StreamData = ByteString
type Fin = Bool
type ReasonPhrase = Bytes
type PathData = Bytes -- 8 bytes
type StatelessResetToken = Bytes -- 16 bytes
