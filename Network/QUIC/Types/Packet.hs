{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Network.QUIC.Types.Packet where

import Data.Ix
import Network.Socket (SockAddr)
import Network.TLS.QUIC (extensionID_QuicTransportParameters, ExtensionID)
import Text.Printf

import Network.QUIC.Imports
import Network.QUIC.Types.Ack
import Network.QUIC.Types.CID
import Network.QUIC.Types.Frame
import Network.QUIC.Types.Time

----------------------------------------------------------------

-- | QUIC version.
newtype Version = Version Word32 deriving (Eq, Ord)

pattern Negotiation      :: Version
pattern Negotiation       = Version 0
pattern Version1         :: Version
pattern Version1          = Version 1
pattern Version2         :: Version
pattern Version2          = Version 0xff020000
pattern Draft29          :: Version
pattern Draft29           = Version 0xff00001d
pattern GreasingVersion  :: Version
pattern GreasingVersion   = Version 0x0a0a0a0a
pattern GreasingVersion2 :: Version
pattern GreasingVersion2  = Version 0x1a2a3a4a

instance Show Version where
    show (Version          0) = "Negotiation"
    show (Version          1) = "Version1"
    show (Version 0xff020000) = "Version2"
    show (Version 0xff00001d) = "Draft29"
    show ver@(Version v)
      | isGreasingVersion ver = "Greasing 0x" ++ printf "%08x" v
      | otherwise             =  "Version 0x" ++ printf "%08x" v

isGreasingVersion :: Version -> Bool
isGreasingVersion (Version v) = v .&. 0x0a0a0a0a == 0x0a0a0a0a

----------------------------------------------------------------

data VersionInfo = VersionInfo {
    chosenVersion :: Version
  , otherVersions :: [Version]
  } deriving (Eq, Show)

defaultVersionInfo :: VersionInfo
defaultVersionInfo = VersionInfo Version1 [Version2, Version1]

brokenVersionInfo :: VersionInfo
brokenVersionInfo = VersionInfo Negotiation []

----------------------------------------------------------------

extensionIDForTtransportParameter :: Version -> ExtensionID
extensionIDForTtransportParameter Version1 = extensionID_QuicTransportParameters
extensionIDForTtransportParameter Version2 = extensionID_QuicTransportParameters
extensionIDForTtransportParameter _        = 0xffa5

----------------------------------------------------------------

data PacketI = PacketIV VersionNegotiationPacket
             | PacketIR RetryPacket
             | PacketIC CryptPacket EncryptionLevel
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

data Plain = Plain {
    plainFlags        :: Flags Raw
  , plainPacketNumber :: PacketNumber
  , plainFrames       :: [Frame]
  , plainMarks        :: Int
  } deriving (Eq, Show)

defaultPlainMarks :: Int
defaultPlainMarks = 0

setIllegalReservedBits :: Int -> Int
setIllegalReservedBits = (`setBit` 0)

setUnknownFrame :: Int -> Int
setUnknownFrame = (`setBit` 1)

setNoFrames :: Int -> Int
setNoFrames = (`setBit` 2)

setNoPaddings :: Int -> Int
setNoPaddings = (`setBit` 8)

set4bytesPN :: Int -> Int
set4bytesPN = (`setBit` 9)

isIllegalReservedBits :: Int -> Bool
isIllegalReservedBits = (`testBit` 0)

isUnknownFrame :: Int -> Bool
isUnknownFrame = (`testBit` 1)

isNoFrames :: Int -> Bool
isNoFrames = (`testBit` 2)

isNoPaddings :: Int -> Bool
isNoPaddings = (`testBit` 8)

is4bytesPN :: Int -> Bool
is4bytesPN = (`testBit` 9)

data MigrationInfo = MigrationInfo SockAddr SockAddr CID deriving (Eq, Show)

data Crypt = Crypt {
    cryptPktNumOffset :: Int
  , cryptPacket       :: ByteString
  , cryptMarks        :: Int
  , cryptMigraionInfo :: Maybe MigrationInfo
  } deriving (Eq, Show)

isCryptDelayed :: Crypt -> Bool
isCryptDelayed crypt = cryptMarks crypt `testBit` 1

setCryptDelayed :: Crypt -> Crypt
setCryptDelayed crypt = crypt { cryptMarks = cryptMarks crypt `setBit` 1 }

data StatelessReset = StatelessReset deriving (Eq, Show)

data ReceivedPacket = ReceivedPacket {
    rpCryptPacket     :: CryptPacket
  , rpTimeRecevied    :: TimeMicrosecond
  , rpReceivedBytes   :: Int
  , rpEncryptionLevel :: EncryptionLevel
  } deriving (Eq, Show)

mkReceivedPacket :: CryptPacket -> TimeMicrosecond -> Int -> EncryptionLevel -> ReceivedPacket
mkReceivedPacket cpkt tim bytes lvl = ReceivedPacket {
    rpCryptPacket     = cpkt
  , rpTimeRecevied    = tim
  , rpReceivedBytes   = bytes
  , rpEncryptionLevel = lvl
  }

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
                     deriving (Eq, Ord, Ix, Show)

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
