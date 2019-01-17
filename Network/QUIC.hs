-- https://quicwg.org/base-drafts/
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE BinaryLiterals #-}

module Network.QUIC where

import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error (throwCryptoError)
import Data.Bits
import Data.ByteArray (convert)
import qualified Data.ByteString as B
import Data.ByteString.Base16
import Data.Int (Int64)
import Network.ByteOrder
import Network.TLS hiding (Version, RTT0, Header)

-- https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#initial-secrets

dec16 :: ByteString -> ByteString
dec16 = fst . decode

enc16 :: ByteString -> ByteString
enc16 = encode

hash :: Hash
hash = SHA256

initial_salt :: ByteString
initial_salt = dec16 "ef4fb0abb47470c41befcf8031334fae485e09a0"

-- https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#test-vectors-initial

cid :: ByteString
cid = dec16 "8394c8f03e515708"

-- "4496d3903d3f97cc5e45ac5790ddc686683c7c0067012bb09d900cc21832d596"
initial_secret :: ByteString
initial_secret = hkdfExtract hash initial_salt cid

-- "8a3515a14ae3c31b9c2d6d5bc58538ca5cd2baa119087143e60887428dcb52f6"
client_initial_secret :: ByteString
client_initial_secret = hkdfExpandLabel hash initial_secret "client in" "" 32

-- "98b0d7e5e7a402c67c33f350fa65ea54"
ckey :: ByteString
ckey = hkdfExpandLabel hash client_initial_secret "quic key" "" 16

-- "19e94387805eb0b46c03a788"
civ :: ByteString
civ = hkdfExpandLabel hash client_initial_secret "quic iv" "" 12

-- "0edd982a6ac527f2eddcbb7348dea5d7"
chp :: ByteString
chp = hkdfExpandLabel hash client_initial_secret "quic hp" "" 16

-- "47b2eaea6c266e32c0697a9e2a898bdf5c4fb3e5ac34f0e549bf2c58581a3811"
server_initial_secret :: ByteString
server_initial_secret = hkdfExpandLabel hash initial_secret "server in" "" 32

-- "9a8be902a9bdd91d16064ca118045fb4"
skey :: ByteString
skey = hkdfExpandLabel hash server_initial_secret "quic key" "" 16

-- "0a82086d32205ba22241d8dc"
siv :: ByteString
siv = hkdfExpandLabel hash server_initial_secret "quic iv" "" 12

--"94b9452d2b3c7c7f6da7fdd8593537fd"
shp :: ByteString
shp = hkdfExpandLabel hash server_initial_secret "quic hp" "" 16

clientCRYPTOframe :: ByteString
clientCRYPTOframe = dec16 $ B.concat [
    "060040c4010000c003036660261ff947cea49cce6cfad687f457cf1b14531ba1"
  , "4131a0e8f309a1d0b9c4000006130113031302010000910000000b0009000006"
  , "736572766572ff01000100000a00140012001d00170018001901000101010201"
  , "03010400230000003300260024001d00204cfdfcd178b784bf328cae793b136f"
  , "2aedce005ff183d7bb1495207236647037002b0003020304000d0020001e0403"
  , "05030603020308040805080604010501060102010402050206020202002d0002"
  , "0101001c00024001"
  ]

-- |
-- >>> decodeInt (dec16 "c2197c5eff14e88c")
-- 151288809941952652
-- >>> decodeInt (dec16 "9d7f3e7d")
-- 494878333
-- >>> decodeInt (dec16 "7bbd")
-- 15293
-- >>> decodeInt (dec16 "25")
-- 37
decodeInt :: ByteString -> IO Int64
decodeInt bs = withReadBuffer bs decodeInt'

decodeInt' :: ReadBuffer -> IO Int64
decodeInt' rbuf = do
    b0 <- read8 rbuf
--    let flag = (b0 .&. 0xc0) `shiftR` 6
    let flag = b0 `shiftR` 6
        b1 = fromIntegral (b0 .&. 0x3f)
    case flag of
      0 -> return b1
      1 -> loop b1 1
      2 -> loop b1 3
      _ -> loop b1 7
  where
    loop :: Int64 -> Int -> IO Int64
    loop !r  0 = return r
    loop !r !n = do
        b <- fromIntegral <$> read8 rbuf
        loop (r*256 + b) (n - 1)

decodeFrames :: ByteString -> IO [Frame]
decodeFrames bs = withReadBuffer bs $ loop id
  where
    loop frames rbuf = do
        ok <- checkSpace rbuf 1
        if ok then do
            frame <- decodeFrame rbuf
            loop ((frame:) . frames) rbuf
          else
            return $ frames []

decodeFrame :: ReadBuffer -> IO Frame
decodeFrame rbuf = do
    b0 <- read8 rbuf
    case b0 of
      0x00 -> return Padding
      0x06 -> decodeCryptoFrame rbuf
      _x   -> error $ show _x

decodeCryptoFrame :: ReadBuffer -> IO Frame
decodeCryptoFrame rbuf = do
    off <- fromIntegral <$> decodeInt' rbuf
    len <- fromIntegral <$> decodeInt' rbuf
    cdata <- extractByteString rbuf len
    return $ Crypto off cdata

-- https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#sample-packet-number-decoding

type PacketNumber = Int64
type EncodedPacketNumber = Int

decodePacketNumber :: PacketNumber -> EncodedPacketNumber -> Int -> PacketNumber
decodePacketNumber largestPN truncatedPN pnNbits
  | candidatePN <= expectedPN - pnHwin = candidatePN + pnWin
  | candidatePN >  expectedPN + pnHwin
 && candidatePN >  pnWin               = candidatePN - pnWin
  | otherwise                          = candidatePN
  where
    expectedPN = largestPN + 1
    pnWin = 1 `shiftL` pnNbits
    pnHwin = pnWin `div` 2
    pnMask = pnWin - 1
    candidatePN = (expectedPN .&. complement pnMask)
              .|. fromIntegral truncatedPN


clientPacketHeader :: ByteString
clientPacketHeader = dec16 "c3ff000012508394c8f03e51570800449f00000002"

-- c3ff000012508394c8f03e51570800449f00000002
-- c3               -- flags
-- ff000012         -- version
-- 50               -- dcil & scil
-- 8394c8f03e515708 -- dest cid
-- 00               -- token length
-- 449f             -- length: decodeInt (dec16 "449f") = 1183 = 4 + 1163 + 16
-- 00000002         -- encoded packet number
                    -- decodePacketNumber 0 2 32 = 2 ???

encryptPayload :: ByteString -> ByteString -> PacketNumber -> ByteString -> ByteString -> ByteString
encryptPayload key iv pn frames header = aes128gcmEncrypt key nonce plain ad
  where
    ivLen = B.length iv
    pnList = loop pn []
    paddedPnList = replicate (ivLen - length pnList) 0 ++ pnList
    nonce = B.pack $ zipWith xor (B.unpack iv) paddedPnList
    plain = frames
    ad = header
    loop 0  !ws = ws
    loop !n !ws = loop (n `shiftR` 8) (fromIntegral n : ws)

aes128gcmEncrypt :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString
aes128gcmEncrypt key nonce plain ad = cipher `B.append` convert tag
  where
    ctx = throwCryptoError (cipherInit key) :: AES128
    aeadIni = throwCryptoError $ aeadInit AEAD_GCM ctx nonce
    (AuthTag tag, cipher) = aeadSimpleEncrypt aeadIni ad plain 16

aes128gcmDecrypt :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString
aes128gcmDecrypt key nonce cipher ad = simpleDecrypt aeadIni ad cipher 16
  where
    ctx = throwCryptoError $ cipherInit key :: AES128
    aeadIni = throwCryptoError $ aeadInit AEAD_GCM ctx nonce

simpleDecrypt :: AEAD cipher -> ByteString -> ByteString -> Int -> ByteString
simpleDecrypt aeadIni header input taglen = output
  where
    aead                 = aeadAppendHeader aeadIni header
    (output, _aeadFinal) = aeadDecrypt aead input
    _tag                 = aeadFinalize _aeadFinal taglen


clientCRYPTOframePadded :: ByteString
clientCRYPTOframePadded = clientCRYPTOframe `B.append` B.pack (replicate 963 0)

encryptedPayload :: ByteString
encryptedPayload = encryptPayload ckey civ 2 clientCRYPTOframePadded clientPacketHeader

-- "0000f3a694c75775b4e546172ce9e047"
sample :: ByteString
sample = B.take 16 encryptedPayload

headerProtection :: ByteString -> ByteString -> ByteString
headerProtection hpKey sampl = ecbEncrypt cipher sampl
  where
    cipher = throwCryptoError (cipherInit hpKey) :: AES128

-- "020dbc1958a7df52e6bbc9ebdfd07828"
mask :: ByteString
mask = headerProtection chp sample


type Length = Int

data Frame = Padding
           | Crypto Offset ByteString
           deriving (Eq,Show)

type DCID = ByteString
type SCID = ByteString
type RawFlags = Word8
data PacketType = Initial | RTT0 | Handshake | Retry
data Version = Draft17 | Negotiation | UnknownVersion Word32
data Header = NegoHeader DCID SCID
            | LongHeader PacketType RawFlags Version DCID SCID

decodePacket :: ReadBuffer -> IO ()
decodePacket rbuf = do
    flags <- read8 rbuf
    _ <- if testBit flags 7 then do
        decodeLongHeader rbuf flags
      else
        decodeShortHeader rbuf flags
    return ()

decodePacketType :: RawFlags -> PacketType
decodePacketType flags = case flags .&. 0b00110000 of
    0b00000000 -> Initial
    0b00010000 -> RTT0
    0b00100000 -> Handshake
    _          -> Retry

decodeVersion :: Word32 -> Version
decodeVersion 0          = Negotiation
decodeVersion 0xff000011 = Draft17
decodeVersion w          = UnknownVersion w

decodeLongHeader :: ReadBuffer -> Word8 -> IO Header
decodeLongHeader rbuf flags = do
    version <- decodeVersion <$> read32 rbuf
    dcil <- fromIntegral <$> read8 rbuf
    scil <- fromIntegral <$> read8 rbuf
    dcID <- extractByteString rbuf dcil
    scID <- extractByteString rbuf scil
    case version of
      Negotiation -> return $ NegoHeader dcID scID
      Draft17     -> do
          let pt = decodePacketType flags
          return $ LongHeader pt flags version dcID scID
      UnknownVersion _ -> error "unknown version"

decodeShortHeader :: ReadBuffer -> Word8 -> IO Header
decodeShortHeader rbuf flags = undefined
