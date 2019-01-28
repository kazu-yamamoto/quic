{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Transport.Packet where

import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.IORef
import Data.List (foldl')
import Foreign.Ptr
import Network.ByteOrder

import Network.QUIC.TLS
import Network.QUIC.Transport.Context
import Network.QUIC.Transport.Frame
import Network.QUIC.Transport.Integer
import Network.QUIC.Transport.Types
import Network.QUIC.Transport.PacketNumber

----------------------------------------------------------------

encodeVersion :: Version -> Word32
encodeVersion Negotiation        = 0
encodeVersion Draft17            = 0xff000011
encodeVersion Draft18            = 0xff000012
encodeVersion (UnknownVersion w) = w

decodeVersion :: Word32 -> Version
decodeVersion 0          = Negotiation
decodeVersion 0xff000011 = Draft17
decodeVersion 0xff000012 = Draft18
decodeVersion w          = UnknownVersion w

----------------------------------------------------------------

encodePacketType :: RawFlags -> PacketType -> RawFlags
encodePacketType flags Initial   = flags
encodePacketType flags RTT0      = flags .|. 0b00010000
encodePacketType flags Handshake = flags .|. 0b00100000
encodePacketType flags Retry     = flags .|. 0b00110000

decodePacketType :: RawFlags -> PacketType
decodePacketType flags = case flags .&. 0b00110000 of
    0b00000000 -> Initial
    0b00010000 -> RTT0
    0b00100000 -> Handshake
    _          -> Retry

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

----------------------------------------------------------------

decodePacket :: Context -> ByteString -> IO (Packet, ByteString)
decodePacket ctx bin = withReadBuffer bin $ \rbuf -> do
    flags <- read8 rbuf
    save rbuf
    pkt <- if testBit flags 7 then do
             decodeLongHeaderPacket ctx rbuf flags
           else
             decodeShortHeaderPacket ctx rbuf flags
    siz <- savingSize rbuf
    let remaining = B.drop (siz + 1) bin
    return (pkt, remaining)

decodeLongHeaderPacket :: Context -> ReadBuffer -> Word8 -> IO Packet
decodeLongHeaderPacket ctx rbuf flags = do
    version <- decodeVersion <$> read32 rbuf
    cil <- fromIntegral <$> read8 rbuf
    let dcil = decodeCIL ((cil .&. 0b11110000) `shiftR` 4)
        scil = decodeCIL (cil .&. 0b1111)
    dcID <- extractByteString rbuf dcil
    scID <- extractByteString rbuf scil
    case version of
      Negotiation      -> decodeVersionNegotiationPacket rbuf dcID scID
      Draft17          -> decodeDraft ctx rbuf flags version dcID scID
      Draft18          -> decodeDraft ctx rbuf flags version dcID scID
      UnknownVersion _ -> error "unknown version"
  where
    decodeCIL 0 = 0
    decodeCIL n = n + 3

decodeDraft :: Context -> ReadBuffer -> RawFlags -> Version -> DCID -> SCID -> IO Packet
decodeDraft ctx rbuf flags version dcID scID = case decodePacketType flags of
    Initial -> decodeInitialPacket ctx rbuf flags version dcID scID
    _       -> undefined

decodeInitialPacket :: Context -> ReadBuffer -> RawFlags -> Version -> DCID -> SCID -> IO Packet
decodeInitialPacket ctx rbuf proFlags version dcID scID = do
    tokenLen <- fromIntegral <$> decodeInt' rbuf
    token <- extractByteString rbuf tokenLen
    len <- fromIntegral <$> decodeInt' rbuf
    cipher <- getCipher ctx
    let secret = case role ctx of
          Client _ -> serverInitialSecret cipher (CID $ connectionID ctx)
          Server _ -> clientInitialSecret cipher (CID dcID)
        hpKey = headerProtectionKey cipher secret
    slen <- savingSize rbuf
    unprotected <- extractByteString rbuf (negate slen)
    sample <- takeSample rbuf $ sampleLength cipher
    let Mask mask = protectionMask cipher hpKey sample
    let Just (mask1,mask2) = B.uncons mask
        flag = proFlags `xor` (mask1 .&. 0b1111)
        pnLen = fromIntegral (flag .&. 0b11) + 1
    bytePN <- bsXOR mask2 <$> extractByteString rbuf pnLen
    encryptedPayload <- extractByteString rbuf (len - pnLen)
    let key = aeadKey cipher secret
        iv  = initialVector cipher secret
        header = B.cons flag (unprotected `B.append` bytePN)
        pn = decodePacketNumber 0 (toEncodedPacketNumber bytePN) (pnLen * 8)
        nonce = makeNonce iv bytePN
    let Just payload = decryptPayload cipher key nonce encryptedPayload (AddDat header)
    frames <- decodeFrames payload
    return $ InitialPacket version dcID scID token pn frames

toEncodedPacketNumber :: ByteString -> EncodedPacketNumber
toEncodedPacketNumber bs = foldl' (\b a -> b * 256 + fromIntegral a) 0 $ B.unpack bs

takeSample :: ReadBuffer -> Int -> IO Sample
takeSample rbuf len = do
    ff rbuf 4
    sample <- extractByteString rbuf len
    ff rbuf $ negate (len + 4)
    return $ Sample sample

decodeVersionNegotiationPacket :: ReadBuffer -> DCID -> SCID -> IO Packet
decodeVersionNegotiationPacket rbuf dcID scID = do
    version <- decodeVersion <$> read32 rbuf
    -- fixme
    return $ VersionNegotiationPacket dcID scID [version]

decodeShortHeaderPacket :: Context -> ReadBuffer -> Word8 -> IO Packet
decodeShortHeaderPacket _ctx _rbuf _flags = undefined