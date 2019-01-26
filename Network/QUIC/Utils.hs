module Network.QUIC.Utils where

import Data.ByteString (ByteString)
import Data.ByteString.Base16

dec16 :: ByteString -> ByteString
dec16 = fst . decode

enc16 :: ByteString -> ByteString
enc16 = encode
