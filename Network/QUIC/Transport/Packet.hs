{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Transport.Packet where

import qualified Data.ByteString as B
import Foreign.Ptr

import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Transport.Context
import Network.QUIC.Transport.Frame
import Network.QUIC.Transport.Integer
import Network.QUIC.Transport.PacketNumber
import Network.QUIC.Transport.Types

----------------------------------------------------------------

encodeVersion :: Version -> Word32
encodeVersion Negotiation        = 0
encodeVersion Draft18            = 0xff000012
encodeVersion Draft19            = 0xff000013
encodeVersion Draft20            = 0xff000014
encodeVersion Draft21            = 0xff000015
encodeVersion Draft22            = 0xff000016
encodeVersion Draft23            = 0xff000017
encodeVersion (UnknownVersion w) = w

decodeVersion :: Word32 -> Version
decodeVersion 0          = Negotiation
decodeVersion 0xff000012 = Draft18
decodeVersion 0xff000013 = Draft19
decodeVersion 0xff000014 = Draft20
decodeVersion 0xff000015 = Draft21
decodeVersion 0xff000016 = Draft22
decodeVersion 0xff000017 = Draft23
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

encrypt :: Cipher -> Secret -> PlainText -> ByteString -> PacketNumber
        -> CipherText
encrypt cipher secret plaintext header pn =
    encryptPayload cipher key nonce plaintext (AddDat header)
  where
    key    = aeadKey cipher secret
    iv     = initialVector cipher secret
    nonce  = makeNonce iv bytePN
    bytePN = bytestring64 (fromIntegral pn)

decrypt :: Cipher -> Secret -> CipherText -> ByteString -> PacketNumber
        -> Maybe PlainText
decrypt cipher secret ciphertext header pn =
    decryptPayload cipher key nonce ciphertext (AddDat header)
  where
    key    = aeadKey cipher secret
    iv     = initialVector cipher secret
    nonce  = makeNonce iv bytePN
    bytePN = bytestring64 (fromIntegral pn)

----------------------------------------------------------------

isLong :: Word8 -> Bool
isLong flags = flags .&. 0x80 == 0x80

flagBits :: Word8 -> Word8
flagBits flags
  | isLong flags = 0b00001111 -- long header
  | otherwise    = 0b00011111 -- short header

protectHeader :: Buffer -> Buffer -> Int -> Cipher -> Secret -> CipherText -> IO ()
protectHeader headerBeg pnBeg epnLen cipher secret ciphertext = do
    flags <- peek8 headerBeg 0
    let protectecFlag = flags `xor` ((mask `B.index` 0) .&. flagBits flags)
    poke8 protectecFlag headerBeg 0
    shuffle 0
    when (epnLen >= 2) $ shuffle 1
    when (epnLen >= 3) $ shuffle 2
    when (epnLen == 4) $ shuffle 3
  where
    ciphertext'
      | epnLen == 1 = B.drop 3 ciphertext
      | epnLen == 2 = B.drop 2 ciphertext
      | epnLen == 3 = B.drop 1 ciphertext
      | otherwise   = ciphertext
    sample = Sample $ B.take (sampleLength cipher) ciphertext'
    hpKey = headerProtectionKey cipher secret
    Mask mask = protectionMask cipher hpKey sample
    shuffle n = do
        p0 <- peek8 pnBeg n
        let pp0 = p0 `xor` (mask `B.index` (n + 1))
        poke8 pp0 pnBeg n

unprotectHeader :: ReadBuffer -> Cipher -> Secret -> Word8
                -> IO (ByteString, Word8, PacketNumber, Int)
unprotectHeader rbuf cipher secret proFlags = do
    -- the cursor is just after the unprotected part of header
    slen <- savingSize rbuf
    unprotected <- extractByteString rbuf (negate slen)
    sample <- takeSample $ sampleLength cipher
    let Mask mask = protectionMask cipher hpKey sample
    let Just (mask1,mask2) = B.uncons mask
        flags = proFlags `xor` (mask1 .&. flagBits proFlags)
        epnLen = fromIntegral (flags .&. 0b11) + 1
    bytePN <- bsXOR mask2 <$> extractByteString rbuf epnLen
    let header = B.cons flags (unprotected `B.append` bytePN)
    let pn = decodePacketNumber 0 (toEncodedPacketNumber bytePN) epnLen
    return (header, flags, pn, epnLen)
    -- the cursor is just after packet number
  where
    hpKey = headerProtectionKey cipher secret

    toEncodedPacketNumber :: ByteString -> EncodedPacketNumber
    toEncodedPacketNumber bs = foldl' (\b a -> b * 256 + fromIntegral a) 0 $ B.unpack bs

    takeSample :: Int -> IO Sample
    takeSample len = do
        ff rbuf maxEPNLen
        sample <- extractByteString rbuf len
        ff rbuf $ negate (len + maxEPNLen)
        return $ Sample sample

maxEPNLen :: Int
maxEPNLen = 4

----------------------------------------------------------------

encodePacket :: Context -> Packet -> IO ByteString
encodePacket ctx pkt = withWriteBuffer 2048 $ \wbuf ->
  encodePacket' ctx wbuf pkt

encodePacket' :: Context -> WriteBuffer -> Packet -> IO ()
encodePacket' _ctx wbuf (VersionNegotiationPacket dcID scID vers) = do
    -- flag
    write8 wbuf 0b10000000
    -- ver .. scID
    encodeLongHeader wbuf Negotiation dcID scID
    -- vers
    mapM_ (write32 wbuf . encodeVersion) vers
    -- no header protection

encodePacket' ctx wbuf (InitialPacket ver dcID scID token pn frames) = do
    -- flag ... scID
    headerBeg <- currentOffset wbuf
    (epn, epnLen) <- encodeLongHeaderPP ctx wbuf Initial ver dcID scID pn
    -- token
    encodeInt' wbuf $ fromIntegral $ B.length token
    copyByteString wbuf token
    -- length .. payload
    let secret = txInitialSecret ctx
        cipher = defaultCipher
    protectPayloadHeader wbuf frames cipher secret pn epn epnLen headerBeg True

encodePacket' ctx wbuf (RTT0Packet ver dcID scID pn frames) = do
    -- flag ... scID
    headerBeg <- currentOffset wbuf
    (epn, epnLen) <- encodeLongHeaderPP ctx wbuf RTT0 ver dcID scID pn
    -- length .. payload
    secret <- undefined ctx
    cipher <- getCipher ctx
    protectPayloadHeader wbuf frames cipher secret pn epn epnLen headerBeg True

encodePacket' ctx wbuf (HandshakePacket ver dcID scID pn frames) = do
    -- flag ... scid
    headerBeg <- currentOffset wbuf
    (epn, epnLen) <- encodeLongHeaderPP ctx wbuf Handshake ver dcID scID pn
    -- length .. payload
    secret <- txHandshakeSecret ctx
    cipher <- getCipher ctx
    protectPayloadHeader wbuf frames cipher secret pn epn epnLen headerBeg True

encodePacket' _ctx wbuf (RetryPacket ver dcID scID (CID odcid) token) = do
    let flags = encodePacketType 0b11000000 Retry
    write8 wbuf flags
    encodeLongHeader wbuf ver dcID scID
    let odcidlen = fromIntegral $ B.length odcid
    write8 wbuf odcidlen
    copyByteString wbuf odcid
    copyByteString wbuf token
    -- no header protection

encodePacket' ctx wbuf (ShortPacket (CID dcid) pn frames) = do
    -- flag
    let (epn, epnLen) = encodePacketNumber 0 {- dummy -} pn
        pp = fromIntegral (epnLen - 1)
        flags = 0b01000000 .|. pp -- fixme: K flag
    headerBeg <- currentOffset wbuf
    write8 wbuf flags
    -- dcID
    copyByteString wbuf dcid
    secret <- txApplicationSecret ctx
    cipher <- getCipher ctx
    protectPayloadHeader wbuf frames cipher secret pn epn epnLen headerBeg False

encodeLongHeader :: WriteBuffer
                 -> Version -> CID -> CID
                 -> IO ()
encodeLongHeader wbuf ver (CID dcid) (CID scid) = do
    write32 wbuf $ encodeVersion ver
    let dcidlen = fromIntegral $ B.length dcid
    write8 wbuf dcidlen
    copyByteString wbuf dcid
    let scidlen = fromIntegral $ B.length scid
    write8 wbuf scidlen
    copyByteString wbuf scid

encodeLongHeaderPP :: Context -> WriteBuffer
                   -> PacketType -> Version -> CID -> CID
                   -> PacketNumber
                   -> IO (EncodedPacketNumber, Int)
encodeLongHeaderPP _ctx wbuf pkttyp ver dcID scID pn = do
    let el@(_, pnLen) = encodePacketNumber 0 {- dummy -} pn
        pp = fromIntegral (pnLen - 1)
        flags' = encodePacketType (0b11000000 .|. pp) pkttyp
    write8 wbuf flags'
    encodeLongHeader wbuf ver dcID scID
    return el

protectPayloadHeader :: WriteBuffer -> [Frame] -> Cipher -> Secret -> PacketNumber -> EncodedPacketNumber -> Int -> Buffer -> Bool -> IO ()
protectPayloadHeader wbuf frames cipher secret pn epn epnLen headerBeg long = do
    plaintext <- encodeFrames frames
    when long $ do
        let len = epnLen + B.length plaintext + 16 -- fixme: crypto overhead
        -- length: assuming 2byte length
        encodeInt'2 wbuf $ fromIntegral len
    pnBeg <- currentOffset wbuf
    if epnLen == 1 then
        write8  wbuf $ fromIntegral epn
      else if epnLen == 2 then
        write16 wbuf $ fromIntegral epn
      else if epnLen == 3 then
        write24 wbuf epn
      else
        write32 wbuf epn
    -- post process
    headerEnd <- currentOffset wbuf
    header <- extractByteString wbuf (negate (headerEnd `minusPtr` headerBeg))
    -- payload
    let ciphertext = encrypt cipher secret plaintext header pn
    copyByteString wbuf ciphertext
    -- protecting header
    protectHeader headerBeg pnBeg epnLen cipher secret ciphertext

----------------------------------------------------------------

decodePacket :: Context -> ByteString -> IO (Packet, ByteString)
decodePacket ctx bin = withReadBuffer bin $ \rbuf -> do
    proFlags <- read8 rbuf
    save rbuf
    pkt <- if testBit proFlags 7 then do
             decodeLongHeaderPacket ctx rbuf proFlags
           else
             decodeShortHeaderPacket ctx rbuf proFlags
    siz <- savingSize rbuf
    let remaining = B.drop (siz + 1) bin
    return (pkt, remaining)

decodeLongHeaderPacket :: Context -> ReadBuffer -> Word8 -> IO Packet
decodeLongHeaderPacket ctx rbuf proFlags = do
    version <- decodeVersion <$> read32 rbuf
    dcIDlen <- fromIntegral <$> read8 rbuf
    dcID <- CID <$> extractByteString rbuf dcIDlen
    scIDlen <- fromIntegral <$> read8 rbuf
    scID <- CID <$> extractByteString rbuf scIDlen
    case version of
      Negotiation      -> decodeVersionNegotiationPacket rbuf dcID scID
      UnknownVersion v -> error $ "unknown version " ++ show v
      _DraftXX         -> decodeDraft ctx rbuf proFlags version dcID scID

decodeVersionNegotiationPacket :: ReadBuffer -> CID -> CID -> IO Packet
decodeVersionNegotiationPacket rbuf dcID scID = do
    siz <- remainingSize rbuf
    vers <- decodeVersions siz id
    return $ VersionNegotiationPacket dcID scID vers
  where
    decodeVersions siz vers
      | siz <  0  = error "decodeVersionNegotiationPacket"
      | siz == 0  = return $ vers []
      | otherwise = do
            ver <- decodeVersion <$> read32 rbuf
            decodeVersions (siz - 4) ((ver :) . vers)

decodeDraft :: Context -> ReadBuffer -> RawFlags -> Version -> CID -> CID -> IO Packet
decodeDraft ctx rbuf proFlags version dcID scID = case decodePacketType proFlags of
    Initial   -> decodeInitialPacket   ctx rbuf proFlags version dcID scID
    RTT0      -> decodeRTT0Packet      ctx rbuf proFlags version dcID scID
    Handshake -> decodeHandshakePacket ctx rbuf proFlags version dcID scID
    Retry     -> decodeRetryPacket     ctx rbuf proFlags version dcID scID

decodeInitialPacket :: Context -> ReadBuffer -> RawFlags -> Version -> CID -> CID -> IO Packet
decodeInitialPacket ctx rbuf proFlags version dcID scID = do
    tokenLen <- fromIntegral <$> decodeInt' rbuf
    token <- extractByteString rbuf tokenLen
    let cipher = defaultCipher
        secret = rxInitialSecret ctx
    (_flags, pn, frames) <- unprotectHeaderPayload rbuf proFlags cipher secret
    return $ InitialPacket version dcID scID token pn frames

decodeRTT0Packet :: Context -> ReadBuffer -> RawFlags -> Version -> CID -> CID -> IO Packet
decodeRTT0Packet ctx rbuf proFlags version dcID scID = do
    cipher <- getCipher ctx
    secret <- undefined ctx
    (_flags, pn, frames) <- unprotectHeaderPayload rbuf proFlags cipher secret
    return $ RTT0Packet version dcID scID pn frames

decodeHandshakePacket :: Context -> ReadBuffer -> RawFlags -> Version -> CID -> CID -> IO Packet
decodeHandshakePacket ctx rbuf proFlags version dcID scID = do
    cipher <- getCipher ctx
    secret <- rxHandshakeSecret ctx
    (_flags, pn, frames) <- unprotectHeaderPayload rbuf proFlags cipher secret
    return $ HandshakePacket version dcID scID pn frames

-- length .. payload
unprotectHeaderPayload :: ReadBuffer -> Word8 -> Cipher -> Secret -> IO (RawFlags, PacketNumber, [Frame])
unprotectHeaderPayload rbuf proFlags cipher secret = do
    let long = isLong proFlags
    len <- if long then
             fromIntegral <$> decodeInt' rbuf
           else
             return 0
    (header, flags, pn, epnLen) <- unprotectHeader rbuf cipher secret proFlags
    pktSiz <- if long then
                return (len - epnLen)
              else
                remainingSize rbuf
    ciphertext <- extractByteString rbuf pktSiz
    let Just payload = decrypt cipher secret ciphertext header pn
    frames <- decodeFrames payload
    return (flags, pn, frames)

decodeRetryPacket :: Context -> ReadBuffer -> RawFlags -> Version -> CID -> CID -> IO Packet
decodeRetryPacket = undefined

decodeShortHeaderPacket :: Context -> ReadBuffer -> Word8 -> IO Packet
decodeShortHeaderPacket ctx rbuf proFlags = do
    let mycid@(CID my) = myCID ctx
        idlen = B.length my
    dcID <- CID <$> extractByteString rbuf idlen
    when (mycid /= dcID) $ error "decodeShortHeaderPacket"
    cipher <- getCipher ctx
    secret <- rxApplicationSecret ctx
    (_flags, pn, frames) <- unprotectHeaderPayload rbuf proFlags cipher secret
    return $ ShortPacket dcID pn frames
