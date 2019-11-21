module Network.QUIC.Transport.Types (
    Bytes
  , Length
  , PacketNumber
  , StreamID
  , EncodedPacketNumber
  , CID
  , myCIDLength
  , newCID
  , fromCID
  , toCID
  , makeCID
  , unpackCID
  , OrigCID(..)
  , Token
  , RawFlags
  , LongHeaderPacketType(..)
  , Version(..)
  , currentDraft
  , PacketType(..)
  , Packet(..)
  , Delay
  , Range
  , Gap
  , CryptoData
  , StreamData
  , Fin
  , FrameType
  , ReasonPhrase
  , PathData
  , StatelessResetToken
  , Frame(..)
  , EncryptionLevel(..)
  , QUICError(..)
  ) where

import Crypto.Random (getRandomBytes)
import qualified Data.ByteString.Short as Short

import qualified Control.Exception as E
import Network.QUIC.Imports
import Network.QUIC.Transport.Error

-- | All internal byte sequences.
--   `ByteString` should be used for FFI related stuff.
type Bytes = ShortByteString

type Length = Int
type PacketNumber = Int64
type StreamID = Int64
type EncodedPacketNumber = Word32

newtype CID = CID Bytes deriving (Eq, Ord)

myCIDLength :: Int
myCIDLength = 8

newCID :: IO CID
newCID = toCID <$> getRandomBytes myCIDLength

toCID :: ByteString -> CID
toCID = CID . Short.toShort

fromCID :: CID -> ByteString
fromCID (CID sbs) = Short.fromShort sbs

makeCID :: ShortByteString -> CID
makeCID = CID

unpackCID :: CID -> (ShortByteString, Word8)
unpackCID (CID sbs) = (sbs, len)
  where
    len = fromIntegral $ Short.length sbs

instance Show CID where
    show (CID cid) = "CID=" ++ shortToString (enc16s cid)

data OrigCID = OCFirst CID | OCRetry CID deriving (Eq, Show)

type Token = ByteString -- to be decrypted
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

data LongHeaderPacketType = LHInitial
                          | LHRTT0
                          | LHHandshake
                          | LHRetry
                          deriving (Eq, Show)

data PacketType = VersionNegotiation
                | Initial
                | RTT0
                | Handshake
                | Retry
                | Short
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
type FrameType = Int
type ReasonPhrase = Bytes
type PathData = Bytes -- 8 bytes
type StatelessResetToken = Bytes -- 16 bytes

data Frame = Padding
           | Ping
           | Ack PacketNumber Delay Range [(Gap,Range)]
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

data EncryptionLevel = InitialLevel
                     | RTT0Level
                     | HandshakeLevel
                     | RTT1Level
                     deriving (Eq, Ord, Show)

data QUICError = PacketIsBroken
               | VersionIsUnknown Version
               | HandshakeRejectedByPeer TransportError
               | ConnectionIsNotOpen
               | HandshakeFailed String
               deriving (Eq, Show)

instance E.Exception QUICError
