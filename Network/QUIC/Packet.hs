module Network.QUIC.Packet (
  -- * Encode
    encodeVersionNegotiationPacket
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
  , decodeFramesBuffer
  , decodeFramesBS
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
  , decryptToken
  ) where

import Network.QUIC.Packet.Decode
import Network.QUIC.Packet.Decrypt
import Network.QUIC.Packet.Encode
import Network.QUIC.Packet.Frame
import Network.QUIC.Packet.Header
import Network.QUIC.Packet.Token
