module Network.QUIC.Transport.Types where

import Data.Int (Int64)
import Network.ByteOrder

type Length = Int
type PacketNumber = Int64
type EncodedPacketNumber = Int

type DCID = ByteString
type SCID = ByteString
type RawFlags = Word8
data PacketType = Initial | RTT0 | Handshake | Retry
data Version = Draft17 | Negotiation | UnknownVersion Word32
data Header = NegoHeader DCID SCID
            | LongHeader PacketType RawFlags Version DCID SCID

data Frame = Padding
           | Crypto Offset ByteString
           deriving (Eq,Show)
