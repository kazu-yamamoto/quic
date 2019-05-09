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
encodeVersion Draft19            = 0xff000013
encodeVersion Draft20            = 0xff000014
encodeVersion (UnknownVersion w) = w

decodeVersion :: Word32 -> Version
decodeVersion 0          = Negotiation
decodeVersion 0xff000011 = Draft17
decodeVersion 0xff000012 = Draft18
decodeVersion 0xff000013 = Draft19
decodeVersion 0xff000014 = Draft20
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

protectHeader :: Buffer -> Buffer -> Cipher -> Secret -> CipherText -> IO ()
protectHeader headerBeg pnBeg cipher secret ciphertext = do
    flags <- peek8 headerBeg 0
    let protectecFlag = flags `xor` ((mask `B.index` 0) .&. 0b00001111)
    poke8 protectecFlag headerBeg 0
    suffle 0
    suffle 1
    suffle 2
    suffle 3
  where
    sample = Sample $ B.take (sampleLength cipher) ciphertext
    hpKey = headerProtectionKey cipher secret
    Mask mask = protectionMask cipher hpKey sample
    suffle n = do
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
        flags = proFlags `xor` (mask1 .&. 0b1111)
        pnLen = fromIntegral (flags .&. 0b11) + 1
    bytePN <- bsXOR mask2 <$> extractByteString rbuf pnLen
    let header = B.cons flags (unprotected `B.append` bytePN)
    let pn = decodePacketNumber 0 (toEncodedPacketNumber bytePN) (pnLen * 8)
    return (header, flags, pn, pnLen)
    -- the cursor is just after packet number
  where
    hpKey = headerProtectionKey cipher secret

    toEncodedPacketNumber :: ByteString -> EncodedPacketNumber
    toEncodedPacketNumber bs = foldl' (\b a -> b * 256 + fromIntegral a) 0 $ B.unpack bs

    takeSample :: Int -> IO Sample
    takeSample len = do
        ff rbuf 4
        sample <- extractByteString rbuf len
        ff rbuf $ negate (len + 4)
        return $ Sample sample

----------------------------------------------------------------

encodePacket :: Context -> Packet -> IO ByteString
encodePacket ctx pkt = withWriteBuffer 2048 $ \wbuf ->
  encodePacket' ctx wbuf pkt

encodePacket' :: Context -> WriteBuffer -> Packet -> IO ()
encodePacket' _ctx _wbuf (VersionNegotiationPacket _ _ _) =
    undefined
encodePacket' ctx wbuf (InitialPacket ver dcID scID token pn frames) = do
    -- pre process
    plaintext <- encodeFrames frames
    let len = B.length plaintext + 4 + 16 -- fixme: 4 bytes PN + crypto overhead
    headerBeg <- currentOffset wbuf
    -- flag ... src conn id
    epn <- encodeLongHeader ctx wbuf 0b00000000 ver dcID scID pn
    -- token
    encodeInt' wbuf $ fromIntegral $ B.length token
    copyByteString wbuf token
    -- length: assuming 2byte length
    encodeInt'2 wbuf $ fromIntegral len
    pnBeg <- currentOffset wbuf
    -- packet number: assuming 4byte encoded packet number
    write32 wbuf epn
    -- post process
    headerEnd <- currentOffset wbuf
    header <- extractByteString wbuf (negate (headerEnd `minusPtr` headerBeg))
    -- payload
    let cipher = defaultCipher
        secret = txInitialSecret ctx
    let ciphertext = encrypt cipher secret plaintext header pn
    copyByteString wbuf ciphertext
    -- protecting header
    protectHeader headerBeg pnBeg cipher secret ciphertext
encodePacket' ctx wbuf (RTT0Packet ver dcid scid _ frames) = do
    _headerOff <- currentOffset wbuf
    pn <- atomicModifyIORef' (packetNumber ctx) $ \n -> (n+1,n)
    _ <- encodeLongHeader ctx wbuf 0b00010000 ver dcid scid pn
    mapM_ (encodeFrame wbuf) frames
--    protectHeader ctx headerOff sampleOff undefined
encodePacket' ctx wbuf (HandshakePacket ver dcid scid _ frames) = do
    -- xxx
    pn <- atomicModifyIORef' (packetNumber ctx) $ \n -> (n+1,n)
    _ <- encodeLongHeader ctx wbuf 0b00100000 ver dcid scid pn
    mapM_ (encodeFrame wbuf) frames
--    protectHeader
encodePacket' ctx wbuf (RetryPacket ver dcid scid _ _) = do
    epn <- encodeLongHeader ctx wbuf 0b00110000 ver dcid scid undefined
    write32 wbuf epn
--    protectHeader
encodePacket' ctx wbuf (ShortPacket _ _ frames) = do
    _pn <- atomicModifyIORef' (packetNumber ctx) $ \n -> (n+1,n)
    epn <- encodeShortHeader
    mapM_ (encodeFrame wbuf) frames
    write32 wbuf epn
--    protectHeader

encodeLongHeader :: Context -> WriteBuffer
                 -> Word8 -> Version -> CID -> CID
                 -> PacketNumber
                 -> IO EncodedPacketNumber
encodeLongHeader _ctx wbuf flags ver (CID dcid) (CID scid) pn = do
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

encodeShortHeader :: IO Word32
encodeShortHeader = undefined

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
    cil <- fromIntegral <$> read8 rbuf
    let dcil = decodeCIL ((cil .&. 0b11110000) `shiftR` 4)
        scil = decodeCIL (cil .&. 0b1111)
    dcID <- CID <$> extractByteString rbuf dcil
    scID <- CID <$> extractByteString rbuf scil
    case version of
      Negotiation      -> decodeVersionNegotiationPacket rbuf dcID scID
      UnknownVersion _ -> error "unknown version"
      _DraftXX         -> decodeDraft ctx rbuf proFlags version dcID scID
  where
    decodeCIL 0 = 0
    decodeCIL n = n + 3

decodeDraft :: Context -> ReadBuffer -> RawFlags -> Version -> CID -> CID -> IO Packet
decodeDraft ctx rbuf proFlags version dcID scID = case decodePacketType proFlags of
    Initial   -> decodeInitialPacket ctx rbuf proFlags version dcID scID
    RTT0      -> undefined
    Handshake -> decodeHandshakePacket ctx rbuf proFlags version dcID scID
    Retry     -> undefined

decodeInitialPacket :: Context -> ReadBuffer -> RawFlags -> Version -> CID -> CID -> IO Packet
decodeInitialPacket ctx rbuf proFlags version dcID scID = do
    tokenLen <- fromIntegral <$> decodeInt' rbuf
    token <- extractByteString rbuf tokenLen
    len <- fromIntegral <$> decodeInt' rbuf
    let cipher = defaultCipher
        secret = rxInitialSecret ctx
    (header, _flags, pn, pnLen) <- unprotectHeader rbuf cipher secret proFlags
    ciphertext <- extractByteString rbuf (len - pnLen)
    let Just payload = decrypt cipher secret ciphertext header pn
    frames <- decodeFrames payload
    return $ InitialPacket version dcID scID token pn frames

decodeHandshakePacket :: Context -> ReadBuffer -> RawFlags -> Version -> CID -> CID -> IO Packet
decodeHandshakePacket ctx rbuf proFlags version dcID scID = do
    len <- fromIntegral <$> decodeInt' rbuf
    cipher <- getCipher ctx
    secret <- rxHandshakeSecret ctx
    (header, _flags, pn, pnLen) <- unprotectHeader rbuf cipher secret proFlags
    ciphertext <- extractByteString rbuf (len - pnLen)
    let Just payload = decrypt cipher secret ciphertext header pn
    frames <- decodeFrames payload
    return $ HandshakePacket version dcID scID pn frames

decodeVersionNegotiationPacket :: ReadBuffer -> CID -> CID -> IO Packet
decodeVersionNegotiationPacket rbuf dcID scID = do
    version <- decodeVersion <$> read32 rbuf
    -- fixme
    return $ VersionNegotiationPacket dcID scID [version]

decodeShortHeaderPacket :: Context -> ReadBuffer -> Word8 -> IO Packet
decodeShortHeaderPacket _ctx _rbuf _flags = undefined
