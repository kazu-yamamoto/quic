{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Packet.Encode (
    encodePacket
  , encodeVersionNegotiationPacket
  , encodeRetryPacket
  , encodePlainPacket
  , encodeVersion
  ) where

import qualified Data.ByteString as B
import Foreign.Ptr

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Packet.Frame
import Network.QUIC.Packet.Header
import Network.QUIC.Packet.Number
import Network.QUIC.Packet.Version
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

headerMaxSize :: BufferSize
headerMaxSize = 128

-- This is not used internally.
encodePacket :: Connection -> PacketO -> IO [ByteString]
encodePacket _    (PacketOV pkt) = (:[]) <$> encodeVersionNegotiationPacket pkt
encodePacket _    (PacketOR pkt) = (:[]) <$> encodeRetryPacket pkt
encodePacket conn (PacketOP pkt) = encodePlainPacket conn pkt

----------------------------------------------------------------

encodeVersionNegotiationPacket :: VersionNegotiationPacket -> IO ByteString
encodeVersionNegotiationPacket (VersionNegotiationPacket dCID sCID vers) = withWriteBuffer headerMaxSize $ \wbuf -> do
    -- fixme: randomizing unused bits
    let flags = versionNegotiationPacketType
    write8 wbuf flags
    -- ver .. sCID
    encodeLongHeader wbuf Negotiation dCID sCID
    -- vers
    mapM_ (write32 wbuf . encodeVersion) vers
    -- no header protection

----------------------------------------------------------------

encodeRetryPacket :: RetryPacket -> IO ByteString
encodeRetryPacket (RetryPacket ver dCID sCID odCID token) = withWriteBuffer headerMaxSize $ \wbuf -> do
    -- fixme: randomizing unused bits
    let flags = retryPacketType
    write8 wbuf flags
    encodeLongHeader wbuf ver dCID sCID
    let (odcid, odcidlen) = unpackCID odCID
    write8 wbuf odcidlen
    copyShortByteString wbuf odcid
    copyByteString wbuf token
    -- no header protection

----------------------------------------------------------------

encodePlainPacket :: Connection -> PlainPacket -> IO [ByteString]
encodePlainPacket conn ppkt = do
    (hdr,bdy) <- encodePlainPacket' conn ppkt
    return [hdr,bdy]

encodePlainPacket' :: Connection -> PlainPacket -> IO (ByteString, ByteString)
encodePlainPacket' conn (PlainPacket (Initial ver dCID sCID token) (Plain flags pn frames)) = withWriteBuffer' headerMaxSize $ \wbuf -> do
    -- flag ... sCID
    headerBeg <- currentOffset wbuf
    (epn, epnLen) <- encodeLongHeaderPP conn wbuf InitialPacketType ver dCID sCID flags pn
    -- token
    encodeInt' wbuf $ fromIntegral $ B.length token
    copyByteString wbuf token
    -- length .. payload
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg InitialLevel

encodePlainPacket' conn (PlainPacket (RTT0 ver dCID sCID) (Plain flags pn frames)) = withWriteBuffer' headerMaxSize $ \wbuf -> do
    -- flag ... sCID
    headerBeg <- currentOffset wbuf
    (epn, epnLen) <- encodeLongHeaderPP conn wbuf RTT0PacketType ver dCID sCID flags pn
    -- length .. payload
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg RTT0Level

encodePlainPacket' conn (PlainPacket (Handshake ver dCID sCID) (Plain flags pn frames)) = withWriteBuffer' headerMaxSize $ \wbuf -> do
    -- flag ... sCID
    headerBeg <- currentOffset wbuf
    (epn, epnLen) <- encodeLongHeaderPP conn wbuf HandshakePacketType ver dCID sCID flags pn
    -- length .. payload
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg HandshakeLevel

encodePlainPacket' conn (PlainPacket (Short dCID) (Plain flags pn frames)) = withWriteBuffer' headerMaxSize $ \wbuf -> do
    -- flag
    let (epn, epnLen) = encodePacketNumber 0 {- dummy -} pn
        pp = encodePktNumLength epnLen
        flags' = encodeShortHeaderFlags flags pp
    headerBeg <- currentOffset wbuf
    write8 wbuf flags'
    -- dCID
    let (dcid, _) = unpackCID dCID
    copyShortByteString wbuf dcid
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg RTT1Level

----------------------------------------------------------------

encodeLongHeader :: WriteBuffer
                 -> Version -> CID -> CID
                 -> IO ()
encodeLongHeader wbuf ver dCID sCID = do
    write32 wbuf $ encodeVersion ver
    let (dcid, dcidlen) = unpackCID dCID
    write8 wbuf dcidlen
    copyShortByteString wbuf dcid
    let (scid, scidlen) = unpackCID sCID
    write8 wbuf scidlen
    copyShortByteString wbuf scid

----------------------------------------------------------------

encodeLongHeaderPP :: Connection -> WriteBuffer
                   -> LongHeaderPacketType -> Version -> CID -> CID
                   -> RawFlags
                   -> PacketNumber
                   -> IO (EncodedPacketNumber, Int)
encodeLongHeaderPP _conn wbuf pkttyp ver dCID sCID flags pn = do
    let el@(_, pnLen) = encodePacketNumber 0 {- dummy -} pn
        pp = encodePktNumLength pnLen
        flags' = encodeLongHeaderFlags pkttyp flags pp
    write8 wbuf flags'
    encodeLongHeader wbuf ver dCID sCID
    return el

----------------------------------------------------------------

protectPayloadHeader :: Connection -> WriteBuffer -> [Frame] -> PacketNumber -> EncodedPacketNumber -> Int -> Buffer -> EncryptionLevel -> IO ByteString
protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg lvl = do
    secret <- getTxSecret conn lvl
    cipher <- getCipher conn lvl
    plaintext <- encodeFrames frames
    when (lvl /= RTT1Level) $ do
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
    -- protecting header
    protectHeader headerBeg pnBeg epnLen cipher secret ciphertext
    return ciphertext

----------------------------------------------------------------

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
