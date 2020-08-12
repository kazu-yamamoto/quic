module Network.QUIC.Packet.Encode (
    encodePacket
  , encodeVersionNegotiationPacket
  , encodeRetryPacket
  , encodePlainPacket
  ) where

import qualified Data.ByteString as B
import Foreign.Ptr

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Packet.Frame
import Network.QUIC.Packet.Header
import Network.QUIC.Packet.Number
import Network.QUIC.Packet.Version
import Network.QUIC.Parameters
import Network.QUIC.TLS
import Network.QUIC.Types

----------------------------------------------------------------

-- | This is not used internally.
encodePacket :: Connection -> PacketO -> IO [ByteString]
encodePacket _    (PacketOV pkt) = (:[]) <$> encodeVersionNegotiationPacket pkt
encodePacket _    (PacketOR pkt) = (:[]) <$> encodeRetryPacket pkt
encodePacket conn (PacketOP pkt) = encodePlainPacket conn pkt Nothing

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

encodePlainPacket :: Connection -> PlainPacket -> Maybe Int -> IO [ByteString]
encodePlainPacket conn ppkt mlen = do
    let (buf,buflen) = headerBuffer conn
    wbuf <- newWriteBuffer buf buflen
    encodePlainPacket' conn wbuf ppkt mlen

encodePlainPacket' :: Connection -> WriteBuffer -> PlainPacket -> Maybe Int -> IO [ByteString]
encodePlainPacket' conn wbuf (PlainPacket (Initial ver dCID sCID token) (Plain flags pn frames)) mlen = do
    -- flag ... sCID
    headerBeg <- currentOffset wbuf
    (epn, epnLen) <- encodeLongHeaderPP conn wbuf InitialPacketType ver dCID sCID flags pn
    -- token
    encodeInt' wbuf $ fromIntegral $ B.length token
    copyByteString wbuf token
    -- length .. payload
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen InitialLevel

encodePlainPacket' conn wbuf (PlainPacket (RTT0 ver dCID sCID) (Plain flags pn frames)) mlen = do
    -- flag ... sCID
    headerBeg <- currentOffset wbuf
    (epn, epnLen) <- encodeLongHeaderPP conn wbuf RTT0PacketType ver dCID sCID flags pn
    -- length .. payload
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen RTT0Level

encodePlainPacket' conn wbuf (PlainPacket (Handshake ver dCID sCID) (Plain flags pn frames)) mlen = do
    -- flag ... sCID
    headerBeg <- currentOffset wbuf
    (epn, epnLen) <- encodeLongHeaderPP conn wbuf HandshakePacketType ver dCID sCID flags pn
    -- length .. payload
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen HandshakeLevel

encodePlainPacket' conn wbuf (PlainPacket (Short dCID) (Plain flags pn frames)) mlen = do
    -- flag
    let (epn, epnLen) = encodePacketNumber 0 {- dummy -} pn
        pp = encodePktNumLength epnLen
    quicBit <- greaseQuicBit <$> getPeerParameters conn
    Flags flags' <- encodeShortHeaderFlags flags pp quicBit
    headerBeg <- currentOffset wbuf
    write8 wbuf flags'
    -- dCID
    let (dcid, _) = unpackCID dCID
    copyShortByteString wbuf dcid
    protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen RTT1Level

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

protectPayloadHeader :: Connection -> WriteBuffer -> [Frame] -> PacketNumber -> EncodedPacketNumber -> Int -> Buffer -> Maybe Int -> EncryptionLevel -> IO [ByteString]
protectPayloadHeader conn wbuf frames pn epn epnLen headerBeg mlen lvl = do
    cipher <- getCipher conn lvl
    let (buf,buflen) = payloadBuffer conn
    (plaintext0,siz) <- encodeFramesWithPadding buf buflen frames
    here <- currentOffset wbuf
    let taglen = tagLength cipher
        plaintext = case mlen of
                      Nothing -> B.take siz plaintext0
                      Just expectedSize ->
                          let headerSize = (here `minusPtr` headerBeg)
                                         + (if lvl /= RTT1Level then 2 else 0)
                                         + epnLen
                              plainSize = expectedSize - headerSize - taglen
                          in B.take plainSize plaintext0
    when (lvl /= RTT1Level) $ do
        let len = epnLen + B.length plaintext + taglen
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
    coder <- getCoder conn lvl
    let ciphertext = encrypt coder plaintext header pn
    if null ciphertext then
        return []
      else do
        -- protecting header
        let makeMask = protect coder
        protectHeader headerBeg pnBeg epnLen cipher makeMask ciphertext
        hdr <- toByteString wbuf
        return (hdr:ciphertext)

----------------------------------------------------------------

-- fixme
protectHeader :: Buffer -> Buffer -> Int -> Cipher -> (Sample -> Mask) -> [CipherText] -> IO ()
protectHeader headerBeg pnBeg epnLen cipher makeMask [ctxt0,tag0] = do
    flags <- Flags <$> peek8 headerBeg 0
    let Flags proFlags = protectFlags flags (mask `B.index` 0)
    poke8 proFlags headerBeg 0
    shuffle 0
    when (epnLen >= 2) $ shuffle 1
    when (epnLen >= 3) $ shuffle 2
    when (epnLen == 4) $ shuffle 3
  where
    ctxt
      | epnLen == 1 = B.drop 3 ctxt0
      | epnLen == 2 = B.drop 2 ctxt0
      | epnLen == 3 = B.drop 1 ctxt0
      | otherwise   = ctxt0
    slen = sampleLength cipher
    clen = B.length ctxt
    -- We assume that clen (the size of ciphertext) is larger than
    -- or equal to sample length (16 bytes) in many cases.
    sample | clen >= slen = Sample $ B.take slen ctxt
           | otherwise    = Sample (ctxt `B.append` B.take (slen - clen) tag0)
    Mask mask = makeMask sample
    shuffle n = do
        p0 <- peek8 pnBeg n
        let pp0 = p0 `xor` (mask `B.index` (n + 1))
        poke8 pp0 pnBeg n
protectHeader _ _ _ _ _ _ = return ()
