{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Crypto.Utils (
    tagLength
  , sampleLength
  , bsXOR
  , calculateIntegrityTag
  ) where

import qualified Data.ByteArray as Byte (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as Short
import Network.TLS hiding (Version)
import Network.TLS.Extra.Cipher

import Network.QUIC.Crypto.Nite
import Network.QUIC.Crypto.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

bsXOR :: ByteString -> ByteString -> ByteString
bsXOR = Byte.xor

----------------------------------------------------------------

tagLength :: Cipher -> Int
tagLength cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = 16
  | cipher == cipher_TLS13_AES128CCM_SHA256        = 16
  | cipher == cipher_TLS13_AES256GCM_SHA384        = 16
  | otherwise                                      = error "tagLength"

sampleLength :: Cipher -> Int
sampleLength cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = 16
  | cipher == cipher_TLS13_AES128CCM_SHA256        = 16
  | cipher == cipher_TLS13_AES256GCM_SHA384        = 16
  | otherwise                                      = error "sampleLength"

----------------------------------------------------------------

calculateIntegrityTag :: Version -> CID -> ByteString -> ByteString
calculateIntegrityTag ver oCID pseudo0 =
    case aes128gcmEncrypt (key ver) (nonce ver) "" (AssDat pseudo) of
      Nothing -> ""
      Just (hdr,bdy) -> hdr `BS.append` bdy
  where
    (ocid, ocidlen) = unpackCID oCID
    pseudo = BS.concat [BS.singleton ocidlen
                       ,Short.fromShort ocid
                       ,pseudo0]
    key Draft29  = Key "\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1"
    key Version1 = Key "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e"
    key Version2 = Key "\x8f\xb4\xb0\x1b\x56\xac\x48\xe2\x60\xfb\xcb\xce\xad\x7c\xcc\x92"
    key _        = Key "not supported"
    nonce Draft29  = Nonce "\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c"
    nonce Version1 = Nonce "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb"
    nonce Version2 = Nonce "\xd8\x69\x69\xbc\x2d\x7c\x6d\x99\x90\xef\xb0\x4a"
    nonce _        = Nonce "not supported"
