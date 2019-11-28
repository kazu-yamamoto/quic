{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Types (
    Bytes
  , Length
  , StreamID
  , EncodedPacketNumber
  , Token
  , emptyToken
  , RawFlags
  , LongHeaderPacketType(..)
  , Version(..)
  , currentDraft
  , Packet(..)
  , Delay
  , CryptoData
  , StreamData
  , Fin
  , FrameType
  , ReasonPhrase
  , PathData
  , StatelessResetToken
  , Frame(..)
  , EncryptionLevel(..)
  , module Network.QUIC.Types.Ack
  , module Network.QUIC.Types.CID
  , module Network.QUIC.Types.Error
  , module Network.QUIC.Types.Integer
  ) where

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.CID
import Network.QUIC.Types.Error
import Network.QUIC.Types.Integer

type Length = Int
type StreamID = Int64
type EncodedPacketNumber = Word32

type Token = ByteString -- to be decrypted
emptyToken :: Token
emptyToken = ""

type RawFlags = Word8

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

data LongHeaderPacketType = Initial
                          | RTT0
                          | Handshake
                          | Retry
                          deriving (Eq, Show)

data EncryptionLevel = InitialLevel
                     | RTT0Level
                     | HandshakeLevel
                     | RTT1Level
                     deriving (Eq, Ord, Show)

data Packet = VersionNegotiationPacket CID CID [Version]
            | InitialPacket    Version CID CID Token PacketNumber [Frame]
            | RTT0Packet       Version CID CID       PacketNumber [Frame]
            | HandshakePacket  Version CID CID       PacketNumber [Frame]
            | RetryPacket      Version CID CID CID Token
            | ShortPacket              CID           PacketNumber [Frame]
             deriving (Eq, Show)

type Delay = Int
type CryptoData = ByteString
type StreamData = ByteString
type Fin = Bool
type FrameType = Int
type ReasonPhrase = Bytes
type PathData = Bytes -- 8 bytes
type StatelessResetToken = Bytes -- 16 bytes

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
