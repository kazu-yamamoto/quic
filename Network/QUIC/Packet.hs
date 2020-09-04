module Network.QUIC.Packet (
  -- * Encode
    encodePacket
  , encodeVersionNegotiationPacket
  , encodeRetryPacket
  , encodePlainPacket
  -- * Decode
  , decodePacket
  , decodePackets
  , decodeCryptPackets
  , decryptCrypt
  , decodeStatelessResetToken
  -- * Frame
  , encodeFrames
  , decodeFrames
  , countZero -- testing
  -- * Header
  , isLong
  , isShort
  , protectFlags
  , unprotectFlags
  , encodeLongHeaderFlags
  , encodeShortHeaderFlags
  , decodeLongHeaderPacketType
  , encodePktNumLength
  , decodePktNumLength
  , versionNegotiationPacketType
  , retryPacketType
  -- * Token
  , CryptoToken(..)
  , isRetryToken
  , generateToken
  , generateRetryToken
  , encryptToken
  -- * Version
  , fromVersion
  , decryptToken
  ) where

import Network.QUIC.Packet.Decode
import Network.QUIC.Packet.Decrypt
import Network.QUIC.Packet.Encode
import Network.QUIC.Packet.Frame
import Network.QUIC.Packet.Header
import Network.QUIC.Packet.Token
import Network.QUIC.Packet.Version
