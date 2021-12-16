{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Packet.Encode (
--    encodePacket
    encodeVersionNegotiationPacket
  , encodeRetryPacket
  , encodePlainPacket
  ) where

import qualified Data.ByteString as BS
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable (peek)

import Network.QUIC.Connection
import Network.QUIC.Crypto
import Network.QUIC.Imports
import Network.QUIC.Packet.Frame
import Network.QUIC.Packet.Header
import Network.QUIC.Packet.Number
import Network.QUIC.Parameters
import Network.QUIC.Types

----------------------------------------------------------------

-- | This is not used internally.
{-
encodePacket :: Connection -> PacketO -> IO [ByteString]
encodePacket _    (PacketOV pkt) = (:[]) <$> encodeVersionNegotiationPacket pkt
encodePacket _    (PacketOR pkt) = (:[]) <$> encodeRetryPacket pkt
encodePacket conn (PacketOP pkt) = fst   <$> encodePlainPacket conn pkt Nothing
-}

----------------------------------------------------------------

encodeVersionNegotiationPacket :: VersionNegotiationPacket -> IO ByteString
encodeVersionNegotiationPacket (VersionNegotiationPacket dCID sCID vers) = withWriteBuffer maximumQUICHeaderSize $ \wbuf -> do
    Flags flags <- versionNegotiationPacketType
    write8 wbuf flags
    -- ver .. sCID
    encodeLongHeader wbuf Negotiation dCID sCID
    -- vers
    mapM_ (\(Version ver) -> write32 wbuf ver) vers
    -- no header protection

----------------------------------------------------------------

encodeRetryPacket :: RetryPacket -> IO ByteString
encodeRetryPacket (RetryPacket ver dCID sCID token (Left odCID)) = withWriteBuffer maximumQUICHeaderSize $ \wbuf -> do
    save wbuf
    Flags flags <- retryPacketType
    write8 wbuf flags
    encodeLongHeader wbuf ver dCID sCID
    copyByteString wbuf token
    siz <- savingSize wbuf
    pseudo0 <- extractByteString wbuf $ negate siz
    let tag = calculateIntegrityTag ver odCID pseudo0
    copyByteString wbuf tag
    -- no header protection
encodeRetryPacket _ = error "encodeRetryPacket"

----------------------------------------------------------------

-- WriteBuffer: protect(header) + encrypt(plain_frames)
-- encodeBuf:   plain_frames

encodePlainPacket :: Connection -> SizedBuffer -> PlainPacket -> Maybe Int -> IO (Int,Int)
encodePlainPacket conn (SizedBuffer buf bufsiz) ppkt@(PlainPacket _ plain) mlen = do
    let mlen' | isNoPaddings (plainMarks plain) = Nothing
              | otherwise                       = mlen
    wbuf <- newWriteBuffer buf bufsiz
    encodePlainPacket' conn wbuf ppkt mlen'

encodePlainPacket' :: Connection -> WriteBuffer -> PlainPacket -> Maybe Int -> IO (Int,Int)
encodePlainPacket' conn wbuf (PlainPacket (Initial ver dCID sCID token) (Plain flags pn frames _)) mlen = do
    headerBeg <- currentOffset wbuf
    -- flag ... sCID
    (epn, epnLen) <- encodeLongHeaderPP conn wbuf InitialPacketType ver dCID sCID flags pn
    -- token
    encodeInt' wbuf $ fromIntegral $ BS.length token
    copyByteString wbuf token
    -- length .. payload
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen InitialLevel False

encodePlainPacket' conn wbuf (PlainPacket (RTT0 ver dCID sCID) (Plain flags pn frames _)) mlen = do
    headerBeg <- currentOffset wbuf
    -- flag ... sCID
    (epn, epnLen) <- encodeLongHeaderPP conn wbuf RTT0PacketType ver dCID sCID flags pn
    -- length .. payload
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen RTT0Level False

encodePlainPacket' conn wbuf (PlainPacket (Handshake ver dCID sCID) (Plain flags pn frames _)) mlen = do
    headerBeg <- currentOffset wbuf
    -- flag ... sCID
    (epn, epnLen) <- encodeLongHeaderPP conn wbuf HandshakePacketType ver dCID sCID flags pn
    -- length .. payload
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen HandshakeLevel False

encodePlainPacket' conn wbuf (PlainPacket (Short dCID) (Plain flags pn frames marks)) mlen = do
    headerBeg <- currentOffset wbuf
    -- flag
    let (epn, epnLen) | is4bytesPN marks = (fromIntegral pn, 4)
                      | otherwise        = encodePacketNumber 0 {- dummy -} pn
        pp = encodePktNumLength epnLen
    quicBit <- greaseQuicBit <$> getPeerParameters conn
    (keyPhase,_) <- getCurrentKeyPhase conn
    Flags flags' <- encodeShortHeaderFlags flags pp quicBit keyPhase
    write8 wbuf flags'
    -- dCID
    let (dcid, _) = unpackCID dCID
    copyShortByteString wbuf dcid
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen RTT1Level keyPhase

----------------------------------------------------------------

encodeLongHeader :: WriteBuffer
                 -> Version -> CID -> CID
                 -> IO ()
encodeLongHeader wbuf (Version ver) dCID sCID = do
    write32 wbuf ver
    let (dcid, dcidlen) = unpackCID dCID
    write8 wbuf dcidlen
    copyShortByteString wbuf dcid
    let (scid, scidlen) = unpackCID sCID
    write8 wbuf scidlen
    copyShortByteString wbuf scid

----------------------------------------------------------------

encodeLongHeaderPP :: Connection -> WriteBuffer
                   -> LongHeaderPacketType -> Version -> CID -> CID
                   -> Flags Raw
                   -> PacketNumber
                   -> IO (EncodedPacketNumber, Int)
encodeLongHeaderPP conn wbuf pkttyp ver dCID sCID flags pn = do
    let el@(_, pnLen) = encodePacketNumber 0 {- dummy -} pn
        pp = encodePktNumLength pnLen
    quicBit <- greaseQuicBit <$> getPeerParameters conn
    Flags flags' <- encodeLongHeaderFlags pkttyp flags pp quicBit
    write8 wbuf flags'
    encodeLongHeader wbuf ver dCID sCID
    return el

----------------------------------------------------------------

protectPayloadHeader :: Connection -> WriteBuffer -> [Frame] -> PacketNumber -> EncodedPacketNumber -> Int -> Buffer -> Maybe Int -> EncryptionLevel -> Bool -> IO (Int,Int)
protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen lvl keyPhase = do
    -- Real size is maximumUdpPayloadSize. But smaller is better.
    let encBuf    = encodeBuf conn
        encBufLen = 1500 - 20 - 8
    payloadWithoutPaddingSiz <- encodeFramesWithPadding encBuf encBufLen frames
    cipher <- getCipher conn lvl
    coder <- getCoder conn lvl keyPhase
    -- before length or packer number
    lengthOrPNBeg <- currentOffset wbuf
    (packetLen, headerLen, plainLen, tagLen, padLen)
        <- calcLen cipher lengthOrPNBeg payloadWithoutPaddingSiz
    when (lvl /= RTT1Level) $ writeLen (epnLen + plainLen + tagLen)
    pnBeg <- currentOffset wbuf
    writeEpn epnLen
    -- payload
    cryptoBeg <- currentOffset wbuf
    plaintext <- mkBS encBuf plainLen
    header <- mkBS headerBeg headerLen
    --
    let sampleBeg = pnBeg `plusPtr` 4
    setSample coder sampleBeg
    len <- encrypt coder cryptoBeg plaintext (AssDat header) pn
    maskBeg <- getMask coder
    --
    if len < 0 || maskBeg == nullPtr then
         return (-1, -1)
       else do
          -- protecting header
          protectHeader headerBeg pnBeg epnLen maskBeg
          return (packetLen, padLen)
  where
    calcLen cipher lengthOrPNBeg payloadWithoutPaddingSiz = do
        let headerLen = (lengthOrPNBeg `minusPtr` headerBeg)
                      -- length: assuming 2byte length
                      + (if lvl /= RTT1Level then 2 else 0)
                      + epnLen
        let tagLen = tagLength cipher
            plainLen = case mlen of
                Nothing          -> payloadWithoutPaddingSiz
                Just expectedLen -> expectedLen - headerLen - tagLen
            packetLen = headerLen + plainLen + tagLen
            padLen = plainLen - payloadWithoutPaddingSiz
        return (packetLen, headerLen, plainLen, tagLen, padLen)
    -- length: assuming 2byte length
    writeLen len = encodeInt'2 wbuf $ fromIntegral len
    writeEpn 1 = write8  wbuf $ fromIntegral epn
    writeEpn 2 = write16 wbuf $ fromIntegral epn
    writeEpn 3 = write24 wbuf epn
    writeEpn _ = write32 wbuf epn

----------------------------------------------------------------

protectHeader :: Buffer -> Buffer -> Int -> Buffer -> IO ()
protectHeader headerBeg pnBeg epnLen maskBeg = do
    shuffleFlag
    shufflePN 0
    when (epnLen >= 2) $ shufflePN 1
    when (epnLen >= 3) $ shufflePN 2
    when (epnLen == 4) $ shufflePN 3
  where
    mask n = peek (maskBeg `plusPtr` n)
    shuffleFlag = do
        flags <- Flags <$> peek8 headerBeg 0
        mask0 <- mask 0
        let Flags proFlags = protectFlags flags mask0
        poke8 proFlags headerBeg 0
    shufflePN n = do
        p0 <- peek8 pnBeg n
        maskn1 <- mask (n + 1)
        let pp0 = p0 `xor` maskn1
        poke8 pp0 pnBeg n

----------------------------------------------------------------

mkBS :: Buffer -> Int -> IO ByteString
mkBS ptr siz = do
    fptr <- newForeignPtr_ ptr
    return $ PS fptr 0 siz
