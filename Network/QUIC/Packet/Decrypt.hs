{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Packet.Decrypt (
    decryptCrypt,
) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import Foreign.Ptr
import Network.ByteOrder

import Network.QUIC.Connection
import Network.QUIC.Crypto
import Network.QUIC.Imports
import Network.QUIC.Packet.Frame
import Network.QUIC.Packet.Header
import Network.QUIC.Packet.Number
import Network.QUIC.Types

----------------------------------------------------------------

decryptCrypt :: Connection -> Crypt -> EncryptionLevel -> IO (Maybe Plain)
decryptCrypt conn Crypt{..} lvl = do
    cipher <- getCipher conn lvl
    protector <- getProtector conn lvl
    let proFlags = Flags (cryptPacket `BS.index` 0)
        sampleOffset = cryptPktNumOffset + 4
        sampleLen = sampleLength cipher
        sample = BS.take sampleLen $ BS.drop sampleOffset cryptPacket
        makeMask = unprotect protector
        -- The mask is empty when we cannot unprotect, and the packet is
        -- dropped at the uncons below.  That is already how a protector
        -- without keys answers; a sample shorter than the cipher asks for
        -- has to join it *here*, because cipherHeaderProtection is not
        -- total in the length of its sample: AES refuses anything that is
        -- not a whole block and ChaCha20 indexes the first four octets.
        -- A peer chooses that length -- the Length field of a long header
        -- decides where the packet ends -- so reaching those with a short
        -- one throws out of here and takes the connection with it.
        Mask mask
            | BS.length sample == sampleLen = makeMask $ Sample sample
            | otherwise = Mask BS.empty
    case BS.uncons mask of
        Nothing -> return Nothing
        Just (mask1, mask2) -> do
            let rawFlags@(Flags flags) = unprotectFlags proFlags mask1
                epnLen = decodePktNumLength rawFlags
                epn = BS.take epnLen $ BS.drop cryptPktNumOffset cryptPacket
                bytePN = bsXOR mask2 epn
                headerLen = cryptPktNumOffset + epnLen
                (proHeader, ciphertext) = BS.splitAt headerLen cryptPacket
            peerPN <- if lvl == RTT1Level then getPeerPacketNumber conn else return 0
            let pn = decodePacketNumber peerPN (toEncodedPacketNumber bytePN) epnLen
            header <- BS.create headerLen $ \p -> do
                void $ copy p proHeader
                poke8 flags p 0
                void $ copy (p `plusPtr` cryptPktNumOffset) $ BS.take epnLen bytePN
            let keyPhase
                    | lvl == RTT1Level = flags `testBit` 2
                    | otherwise = False
            coder <- getCoder conn lvl keyPhase
            siz <- decrypt coder (decryptBuf conn) ciphertext (AssDat header) pn
            let rrMask
                    | lvl == RTT1Level = 0x18
                    | otherwise = 0x0c
                marks
                    | flags .&. rrMask == 0 = defaultPlainMarks
                    | otherwise = setIllegalReservedBits defaultPlainMarks
            if siz < 0
                then return Nothing
                else do
                    mframes <- decodeFramesBuffer (decryptBuf conn) siz
                    case mframes of
                        Nothing -> do
                            let marks' = setUnknownFrame marks
                            return $ Just $ Plain rawFlags pn [] marks'
                        Just frames -> do
                            let marks'
                                    | null frames = setNoFrames marks
                                    | otherwise = marks
                            return $ Just $ Plain rawFlags pn frames marks'

toEncodedPacketNumber :: ByteString -> EncodedPacketNumber
toEncodedPacketNumber bs = foldl' (\b a -> b * 256 + fromIntegral a) 0 $ BS.unpack bs
