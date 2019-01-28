{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Transport.Encode where

import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.IORef
import Data.Int (Int64)
import Network.ByteOrder
import Foreign.Ptr

import Network.QUIC.TLS
import Network.QUIC.Transport.Context
import Network.QUIC.Transport.Types

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Network.QUIC.Utils

----------------------------------------------------------------

-- |
-- >>> enc16 <$> encodeInt 151288809941952652
-- "c2197c5eff14e88c"
-- >>> enc16 <$> encodeInt 494878333
-- "9d7f3e7d"
-- >>> enc16 <$> encodeInt 15293
-- "7bbd"
-- >>> enc16 <$> encodeInt 37
-- "25"
encodeInt :: Int64  -> IO ByteString
encodeInt i = withWriteBuffer 8 $ \wbuf -> encodeInt' wbuf i

encodeInt' :: WriteBuffer -> Int64 -> IO ()
encodeInt' wbuf i
  | i <=         63 = do
        let [w0] = decomp 1 [] i
        write8 wbuf w0
  | i <=      16383 = do
        let [w0,w1] = decomp 2 [] i
        write8 wbuf (w0 .|. 0b01000000)
        write8 wbuf w1
  | i <= 1073741823 = do
        let [w0,w1,w2,w3] = decomp 4 [] i
        write8 wbuf (w0 .|. 0b10000000)
        write8 wbuf w1
        write8 wbuf w2
        write8 wbuf w3
  | otherwise       = do
        let [w0,w1,w2,w3,w4,w5,w6,w7] = decomp 8 [] i
        write8 wbuf (w0 .|. 0b11000000)
        write8 wbuf w1
        write8 wbuf w2
        write8 wbuf w3
        write8 wbuf w4
        write8 wbuf w5
        write8 wbuf w6
        write8 wbuf w7

encodeInt'2 :: Buffer -> Int64 -> IO ()
encodeInt'2 wbuf i = do
    let [w0,w1] = decomp 2 [] i
    poke8 (w0 .|. 0b01000000) wbuf 0
    poke8 w1 wbuf 1

decomp :: Int -> [Word8] -> Int64 -> [Word8]
decomp 0 ws _ = ws
decomp n ws x = decomp (n-1) (w:ws) x'
  where
    x' = x `shiftR` 8
    w  = fromIntegral x

----------------------------------------------------------------

-- from draft18. We cannot use becase 32 is hard-coded in our impl.
-- encodePacketNumber 0xabe8bc 0xac5c02 == (0x5c02,16)
-- encodePacketNumber 0xa82f30ea 0xa82f9b32 == (0x9b32,16)
encodePacketNumber :: PacketNumber -> PacketNumber -> (EncodedPacketNumber, Int)
encodePacketNumber _largestPN pn = (diff, 32)
  where
    diff = fromIntegral (pn .&. 0xffffffff)

----------------------------------------------------------------

encodeFrames :: [Frame] -> IO ByteString
encodeFrames frames = withWriteBuffer 2048 $ \wbuf ->
  mapM_ (encodeFrame wbuf) frames

encodeFrame :: WriteBuffer -> Frame -> IO ()
encodeFrame wbuf Padding = write8 wbuf 0x00
encodeFrame wbuf (Crypto off cdata) = do
    write8 wbuf 0x06
    encodeInt' wbuf $ fromIntegral off
    encodeInt' wbuf $ fromIntegral $ B.length cdata
    copyByteString wbuf cdata
encodeFrame wbuf (Ack la ad arc far) = do
    write8 wbuf 0x02
    encodeInt' wbuf la
    encodeInt' wbuf ad
    encodeInt' wbuf arc
    encodeInt' wbuf far

----------------------------------------------------------------

-- fixme: using encryptPayload

encodePacket :: Context -> Packet -> IO ByteString
encodePacket ctx pkt = withWriteBuffer 2048 $ \wbuf ->
  encodePacket' ctx wbuf pkt

encodePacket' :: Context -> WriteBuffer -> Packet -> IO ()
encodePacket' _ctx _wbuf (VersionNegotiationPacket _ _ _) =
    undefined
encodePacket' ctx wbuf (InitialPacket ver dcID scID token pn frames) = do
    headerBeg <- currentOffset wbuf
    epn <- encodeLongHeader ctx wbuf 0b00000000 ver dcID scID pn
    encodeInt' wbuf $ fromIntegral $ B.length token
    copyByteString wbuf token
    lenOff <- currentOffset wbuf
    -- assuming 2byte length
    ff wbuf 2
    pnBeg <- currentOffset wbuf
    write32 wbuf epn -- assuming 4byte encoded packet number
    headerEnd <- currentOffset wbuf
    let bytePN = bytestring32 epn
    cipher <- getCipher ctx
    payload <- encodeFrames frames
    let len = B.length payload + 4 + 16 -- fixme
    encodeInt'2 lenOff $ fromIntegral len
    header <- extractByteString wbuf (negate (headerEnd `minusPtr` headerBeg))
    let secret = case role ctx of
          Client _ -> clientInitialSecret cipher (CID dcID)
          Server _ -> serverInitialSecret cipher (CID $ connectionID ctx)
    let key = aeadKey cipher secret
        iv  = initialVector cipher secret
        nonce = makeNonce iv bytePN
    let encryptedPayload = encryptPayload cipher key nonce payload (AddDat header)
    copyByteString wbuf encryptedPayload
    protectHeader ctx headerBeg pnBeg secret encryptedPayload
encodePacket' ctx wbuf (RTT0Packet ver dcid scid _ frames) = do
    _headerOff <- currentOffset wbuf
    pn <- atomicModifyIORef' (appDataSpace ctx) $ \n -> (n+1,n)
    _ <- encodeLongHeader ctx wbuf 0b00010000 ver dcid scid pn
    mapM_ (encodeFrame wbuf) frames
--    protectHeader ctx headerOff sampleOff undefined
encodePacket' ctx wbuf (HandshakePacket ver dcid scid _ frames) = do
    pn <- atomicModifyIORef' (handshakeSpace ctx) $ \n -> (n+1,n)
    _ <- encodeLongHeader ctx wbuf 0b00100000 ver dcid scid pn
    mapM_ (encodeFrame wbuf) frames
--    protectHeader
encodePacket' ctx wbuf (RetryPacket ver dcid scid _ _) = do
    epn <- encodeLongHeader ctx wbuf 0b00110000 ver dcid scid undefined
    write32 wbuf epn
--    protectHeader
encodePacket' ctx wbuf (ShortPacket _ _ frames) = do
    _pn <- atomicModifyIORef' (appDataSpace ctx) $ \n -> (n+1,n)
    epn <- encodeShortHeader
    mapM_ (encodeFrame wbuf) frames
    write32 wbuf epn
--    protectHeader

encodePacketType :: RawFlags -> PacketType -> RawFlags
encodePacketType flags Initial   = flags
encodePacketType flags RTT0      = flags .|. 0b00010000
encodePacketType flags Handshake = flags .|. 0b00100000
encodePacketType flags Retry     = flags .|. 0b00110000

encodeVersion :: Version -> Word32
encodeVersion Negotiation        = 0
encodeVersion Draft17            = 0xff000011
encodeVersion Draft18            = 0xff000012
encodeVersion (UnknownVersion w) = w

encodeLongHeader :: Context -> WriteBuffer
                 -> Word8 -> Version -> DCID -> SCID
                 -> PacketNumber
                 -> IO EncodedPacketNumber
encodeLongHeader _ctx wbuf flags ver dcid scid pn = do
    let (epn, pnLen) = encodePacketNumber 0 {- dummy -} pn
    let pp = fromIntegral ((pnLen `div` 8) - 1)
    let flags' = 0b11000000 .|. flags .|. pp
    write8 wbuf flags'
    write32 wbuf $ encodeVersion ver
    let dcil = fromIntegral $ B.length dcid
        scil = fromIntegral $ B.length scid
        cil = (encodeCIL dcil `shiftL` 4) .|. scil
    write8 wbuf cil
    copyByteString wbuf dcid
    copyByteString wbuf scid
    return epn
  where
    encodeCIL 0 = 0
    encodeCIL n = n - 3

protectHeader :: Context -> Buffer -> Buffer -> Secret -> ByteString -> IO ()
protectHeader ctx headerBeg pnBeg secret payload = do
    cipher <- readIORef $ cipherRef ctx
    let sample = Sample $ B.take (sampleLength cipher) payload
    let key = headerProtectionKey cipher secret
        Mask mask = protectionMask cipher key sample
    flag <- peek8 headerBeg 0
    let protectecFlag = flag `xor` ((mask `B.index` 0) .&. 0b00001111)
    poke8 protectecFlag headerBeg 0
    suffle mask 0
    suffle mask 1
    suffle mask 2
    suffle mask 3
  where
    suffle mask n = do
        p0 <- peek8 pnBeg n
        let pp0 = p0 `xor` (mask `B.index` (n + 1))
        poke8 pp0 pnBeg n

encodeShortHeader :: IO Word32
encodeShortHeader = undefined
