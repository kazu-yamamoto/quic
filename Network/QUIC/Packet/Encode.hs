module Network.QUIC.Packet.Encode (
--    encodePacket
    encodeVersionNegotiationPacket
  , encodeRetryPacket
  , encodePlainPacket
  ) where

import qualified Data.ByteString as BS
import Foreign.ForeignPtr (withForeignPtr, newForeignPtr_)
import Foreign.Ptr

import Network.QUIC.Connection
import Network.QUIC.Crypto
import Network.QUIC.Imports
import Network.QUIC.Packet.Frame
import Network.QUIC.Packet.Header
import Network.QUIC.Packet.Number
import Network.QUIC.Packet.Version
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
    mapM_ (write32 wbuf . encodeVersion) vers
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

encodePlainPacket :: Connection -> Buffer -> BufferSize -> PlainPacket -> Maybe Int -> IO (Int,Int)
encodePlainPacket conn buf bufsiz ppkt@(PlainPacket _ plain) mlen = do
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
protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen lvl keyPhase = withForeignPtr encodeFBuf $ \encodeBuf -> do
    payloadWithoutPaddingSiz <- encodeFramesWithPadding encodeBuf encodeBufLen frames
    cipher <- getCipher conn lvl
    (packetLen, headerLen, plainLen, tagLen, padLen)
        <- calcLen cipher payloadWithoutPaddingSiz
    writeLen $ epnLen + plainLen + tagLen
    pnBeg <- currentOffset wbuf
    writeEpn epnLen
    -- payload
    coder <- getCoder conn lvl keyPhase
    cryptoBeg <- currentOffset wbuf
    -- fixme: error handling
    encrypt coder encodeBuf plainLen headerBeg headerLen pn cryptoBeg
    -- protecting header
    protector <- getProtector conn lvl
    fptr <- newForeignPtr_ cryptoBeg
    let makeMask = protect protector
        ctxt = PS fptr 0 (plainLen + tagLen)
    protectHeader headerBeg pnBeg epnLen cipher makeMask ctxt
    return (packetLen, padLen)
  where
    (encodeFBuf,encodeBufLen) = encodeBuffer conn
    calcLen cipher payloadWithoutPaddingSiz = do
        here <- currentOffset wbuf
        let headerLen = (here `minusPtr` headerBeg)
                      + (if lvl /= RTT1Level then 2 else 0)
                      + epnLen
        let tagLen = tagLength cipher
            plainLen = case mlen of
                Nothing          -> payloadWithoutPaddingSiz
                Just expectedLen -> expectedLen - headerLen - tagLen
            packetLen = headerLen + plainLen + tagLen
            padLen = plainLen - payloadWithoutPaddingSiz
        return (packetLen, headerLen, plainLen, tagLen, padLen)
    writeLen len = when (lvl /= RTT1Level) $ do
        -- length: assuming 2byte length
        encodeInt'2 wbuf $ fromIntegral len
    writeEpn 1 = write8  wbuf $ fromIntegral epn
    writeEpn 2 = write16 wbuf $ fromIntegral epn
    writeEpn 3 = write24 wbuf epn
    writeEpn _ = write32 wbuf epn

----------------------------------------------------------------

protectHeader :: Buffer -> Buffer -> Int -> Cipher -> (Sample -> Mask) -> CipherText -> IO ()
protectHeader headerBeg pnBeg epnLen cipher makeMask ctxt1 = do
    flags <- Flags <$> peek8 headerBeg 0
    let Flags proFlags = protectFlags flags (mask `BS.index` 0)
    poke8 proFlags headerBeg 0
    shuffle 0
    when (epnLen >= 2) $ shuffle 1
    when (epnLen >= 3) $ shuffle 2
    when (epnLen == 4) $ shuffle 3
  where
    slen = sampleLength cipher
    ctxt2 = BS.drop (4 - epnLen) ctxt1
    sample = Sample $ BS.take slen ctxt2
    -- throw an exception if length sample < slen
    Mask mask = makeMask sample
    shuffle n = do
        p0 <- peek8 pnBeg n
        let pp0 = p0 `xor` (mask `BS.index` (n + 1))
        poke8 pp0 pnBeg n
