module Network.QUIC.Packet.Version (
    encodeVersion
  , decodeVersion
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
decodeVersion w          = UnknownVersion w
