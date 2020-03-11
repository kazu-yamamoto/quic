module Network.QUIC.Packet.Version (
    encodeVersion
  , decodeVersion
  , fromVersion
  ) where

import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

encodeVersion :: Version -> Word32
encodeVersion Negotiation        = 0
encodeVersion Draft18            = 0xff000012
encodeVersion Draft19            = 0xff000013
encodeVersion Draft20            = 0xff000014
encodeVersion Draft21            = 0xff000015
encodeVersion Draft22            = 0xff000016
encodeVersion Draft23            = 0xff000017
encodeVersion Draft24            = 0xff000018
encodeVersion Draft25            = 0xff000019
encodeVersion Draft26            = 0xff00001a
encodeVersion Draft27            = 0xff00001b
encodeVersion GreasingVersion    = 0x0a0a0a0a
encodeVersion (UnknownVersion w) = w

----------------------------------------------------------------

decodeVersion :: Word32 -> Version
decodeVersion 0          = Negotiation
decodeVersion 0xff000012 = Draft18
decodeVersion 0xff000013 = Draft19
decodeVersion 0xff000014 = Draft20
decodeVersion 0xff000015 = Draft21
decodeVersion 0xff000016 = Draft22
decodeVersion 0xff000017 = Draft23
decodeVersion 0xff000018 = Draft24
decodeVersion 0xff000019 = Draft25
decodeVersion 0xff00001a = Draft26
decodeVersion 0xff00001b = Draft27
decodeVersion 0xff00ff00 = GreasingVersion
decodeVersion w          = UnknownVersion w

----------------------------------------------------------------

-- | Extracting a draft version. This would be obsoleted in the future.
fromVersion :: Version -> Int
fromVersion ver = fromIntegral (0x000000ff .&. encodeVersion ver)
