module Network.QUIC.Transport.Types where

import Data.Int (Int64)
import Network.ByteOrder

type Length = Int
type PacketNumber = Int64
type EncodedPacketNumber = Word32

newtype CID = CID ByteString deriving (Eq, Show)
type Token = ByteString
type RawFlags = Word8

data PacketType = Initial | RTT0 | Handshake | Retry
                deriving (Eq, Show)

data Version = Negotiation
             | Draft17
             | Draft18
             | UnknownVersion Word32
             deriving (Eq, Show)

data Packet = VersionNegotiationPacket CID CID [Version]
            | InitialPacket    Version CID CID Token PacketNumber [Frame]
            | RTT0Packet       Version CID CID       PacketNumber [Frame]
            | HandshakePacket  Version CID CID       PacketNumber [Frame]
            | RetryPacket      Version CID CID CID Token
            | ShortPacket              CID            PacketNumber [Frame]
             deriving (Eq, Show)

data Frame = Padding
           | Ack Int64 Int64 Int64 Int64 -- fixme
           | Crypto Offset ByteString
           deriving (Eq,Show)
