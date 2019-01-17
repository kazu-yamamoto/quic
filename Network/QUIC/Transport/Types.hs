module Network.QUIC.Transport.Types where

import Data.Int (Int64)
import Network.ByteOrder

type Length = Int
type PacketNumber = Int64
type EncodedPacketNumber = Int

type DCID = ByteString
type SCID = ByteString
type Token = ByteString
type RawFlags = Word8

data PacketType = Initial | RTT0 | Handshake | Retry
                deriving (Eq, Show)

data Version = Draft17 | Negotiation | UnknownVersion Word32
             deriving (Eq, Show)

data Header = NegoHeader DCID SCID
            | InitialHeader RawFlags Version DCID SCID Token Length PacketNumber
             deriving (Eq, Show)

data Frame = Padding
           | Crypto Offset ByteString
           deriving (Eq,Show)
