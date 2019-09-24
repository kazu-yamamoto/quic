module Network.QUIC.Transport.Types where

import qualified Data.ByteString.Char8 as C8

import Network.QUIC.Imports

type Length = Int
type PacketNumber = Int64
type StreamID = Int64
type EncodedPacketNumber = Word32

newtype CID = CID ByteString deriving (Eq)

instance Show CID where
    show (CID cid) = C8.unpack $ enc16 cid

type Token = ByteString
type RawFlags = Word8

data PacketType = Initial | RTT0 | Handshake | Retry
                deriving (Eq, Show)

data Version = Negotiation
             | Draft18
             | Draft19
             | Draft20
             | Draft21
             | Draft22
             | Draft23
             | UnknownVersion Word32
             deriving (Eq, Show)

data Packet = VersionNegotiationPacket CID CID [Version]
            | InitialPacket    Version CID CID Token PacketNumber [Frame]
            | RTT0Packet       Version CID CID       PacketNumber [Frame]
            | HandshakePacket  Version CID CID       PacketNumber [Frame]
            | RetryPacket      Version CID CID CID Token
            | ShortPacket              CID           PacketNumber [Frame]
             deriving (Eq, Show)

type Delay = Int
type Range = Int
type Gap   = Int
type CryptoData = ByteString
type StreamData = ByteString
type Fin = Bool
type ErrorCode = Int

data Frame = Padding
           | Ping
           | Ack PacketNumber Delay Range [(Gap,Range)]
           | Crypto Offset CryptoData
           | Stream StreamID Offset StreamData Fin
           | ConnectionClose ErrorCode ByteString
           deriving (Eq,Show)
