{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Crypto.Nite (
    niteEncrypt,
    niteEncrypt',
    niteDecrypt,
    niteDecrypt',
    protectionMask,
    aes128gcmEncrypt,
    makeNonce,
    makeNiteEncrypt,
    makeNiteDecrypt,
    makeNiteProtector,
) where

import Crypto.Cipher.AES
import Crypto.Cipher.Types hiding (Cipher, IV)
import Crypto.Error (maybeCryptoError, CryptoFailable (..))
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly
import qualified Data.ByteArray as Byte (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import Foreign.ForeignPtr (newForeignPtr_, withForeignPtr)
import Foreign.Marshal.Alloc (mallocBytes)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, nullPtr, plusPtr)
import Foreign.Storable (peek, poke)
import Network.TLS hiding (Version)
import Network.TLS.Extra.Cipher

import Network.QUIC.Crypto.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

-- It would be nice to take [PlainText] and update AEAD context with
-- [PlainText]. But since each PlainText is not aligned to cipher block,
-- it's impossible.
cipherEncrypt
    :: Cipher -> Key -> Nonce -> PlainText -> AssDat -> Maybe (CipherText, CipherText)
cipherEncrypt cipher
    | cipher == cipher13_AES_128_GCM_SHA256 = aes128gcmEncrypt
    | cipher == cipher13_AES_128_CCM_SHA256 = error "cipher13_AES_128_CCM_SHA256"
    | cipher == cipher13_AES_256_GCM_SHA384 = aes256gcmEncrypt
    | cipher == cipher13_CHACHA20_POLY1305_SHA256 = chacha20poly1305Encrypt
    | otherwise = error "cipherEncrypt"

cipherDecrypt
    :: Cipher -> Key -> Nonce -> CipherText -> AssDat -> Maybe PlainText
cipherDecrypt cipher
    | cipher == cipher13_AES_128_GCM_SHA256 = aes128gcmDecrypt
    | cipher == cipher13_AES_128_CCM_SHA256 = error "cipher13_AES_128_CCM_SHA256"
    | cipher == cipher13_AES_256_GCM_SHA384 = aes256gcmDecrypt
    | cipher == cipher13_CHACHA20_POLY1305_SHA256 = chacha20poly1305Decrypt
    | otherwise = error "cipherDecrypt"

-- IMPORTANT: Using 'let' so that parameters can be memorized.
aes128gcmEncrypt
    :: Key -> (Nonce -> PlainText -> AssDat -> Maybe (CipherText, CipherText))
aes128gcmEncrypt (Key key) = case maybeCryptoError $ cipherInit key of
    Nothing -> \_ _ _ -> Nothing
    Just (aes :: AES128) -> \(Nonce nonce) plaintext (AssDat ad) ->
        case maybeCryptoError $ aeadInit AEAD_GCM aes nonce of
            Nothing -> Nothing
            Just aead ->
                let (AuthTag tag0, ciphertext) = aeadSimpleEncrypt aead ad plaintext 16
                    tag = Byte.convert tag0
                 in Just (ciphertext, tag)

aes128gcmDecrypt :: Key -> (Nonce -> CipherText -> AssDat -> Maybe PlainText)
aes128gcmDecrypt (Key key) = case maybeCryptoError $ cipherInit key of
    Nothing -> \_ _ _ -> Nothing
    Just (aes :: AES128) -> \(Nonce nonce) ciphertag (AssDat ad) ->
        case maybeCryptoError $ aeadInit AEAD_GCM aes nonce of
            Nothing -> Nothing
            Just aead ->
                let (ciphertext, tag) = BS.splitAt (BS.length ciphertag - 16) ciphertag
                    authtag = AuthTag $ Byte.convert tag
                 in aeadSimpleDecrypt aead ad ciphertext authtag

aes256gcmEncrypt
    :: Key -> (Nonce -> PlainText -> AssDat -> Maybe (CipherText, CipherText))
aes256gcmEncrypt (Key key) = case maybeCryptoError $ cipherInit key of
    Nothing -> \_ _ _ -> Nothing
    Just (aes :: AES256) -> \(Nonce nonce) plaintext (AssDat ad) ->
        case maybeCryptoError $ aeadInit AEAD_GCM aes nonce of
            Nothing -> Nothing
            Just aead ->
                let (AuthTag tag0, ciphertext) = aeadSimpleEncrypt aead ad plaintext 16
                    tag = Byte.convert tag0
                 in Just (ciphertext, tag)

aes256gcmDecrypt :: Key -> (Nonce -> CipherText -> AssDat -> Maybe PlainText)
aes256gcmDecrypt (Key key) = case maybeCryptoError $ cipherInit key of
    Nothing -> \_ _ _ -> Nothing
    Just (aes :: AES256) -> \(Nonce nonce) ciphertag (AssDat ad) ->
        case maybeCryptoError $ aeadInit AEAD_GCM aes nonce of
            Nothing -> Nothing
            Just aead ->
                let (ciphertext, tag) = BS.splitAt (BS.length ciphertag - 16) ciphertag
                    authtag = AuthTag $ Byte.convert tag
                 in aeadSimpleDecrypt aead ad ciphertext authtag

chacha20poly1305Encrypt
    :: Key -> (Nonce -> PlainText -> AssDat -> Maybe (CipherText, CipherText))
chacha20poly1305Encrypt (Key key) (Nonce nonce) plaintext (AssDat ad) =
    case ChaChaPoly.nonce12 nonce of
        CryptoFailed _ -> Nothing
        CryptoPassed chachaNonce -> case ChaChaPoly.initialize key chachaNonce of
            CryptoFailed _ -> Nothing
            CryptoPassed st0 ->
                let st1 = ChaChaPoly.finalizeAAD (ChaChaPoly.appendAAD ad st0)
                    (ciphertext, st2) = ChaChaPoly.encrypt plaintext st1
                    authTag = ChaChaPoly.finalize st2
                    tag = Byte.convert authTag
                in Just (ciphertext, tag)

chacha20poly1305Decrypt :: Key -> (Nonce -> CipherText -> AssDat -> Maybe PlainText)
chacha20poly1305Decrypt (Key key) (Nonce nonce) ciphertag (AssDat ad) =
    case ChaChaPoly.nonce12 nonce of
        CryptoFailed _ -> Nothing
        CryptoPassed chachaNonce -> case ChaChaPoly.initialize key chachaNonce of
            CryptoFailed _ -> Nothing
            CryptoPassed st0 ->
                let (ciphertext, expectedTag) = BS.splitAt (BS.length ciphertag - 16) ciphertag
                    st1 = ChaChaPoly.finalizeAAD (ChaChaPoly.appendAAD ad st0)
                    (plaintext, st2) = ChaChaPoly.decrypt ciphertext st1
                    actualTag = ChaChaPoly.finalize st2
                in if Byte.convert actualTag == expectedTag
                    then Just plaintext
                    else Nothing
----------------------------------------------------------------

makeNonce :: IV -> ByteString -> Nonce
makeNonce (IV iv) pn = Nonce nonce
  where
    nonce = bsXORpad iv pn

-- XORing IV and a packet numbr with left padded.
--             src0
-- IV          +IIIIIIIIIIIIIIIIII--------+
--                 diff          src1
-- PN          +000000000000000000+-------+
--             dst
-- Nonce       +IIIIIIIIIIIIIIIIII--------+
bsXORpad :: ByteString -> ByteString -> ByteString
bsXORpad (PS fp0 off0 len0) (PS fp1 off1 len1)
    | len0 < len1 = error "bsXORpad"
    | otherwise = BS.unsafeCreate len0 $ \dst ->
        withForeignPtr fp0 $ \p0 ->
            withForeignPtr fp1 $ \p1 -> do
                let src0 = p0 `plusPtr` off0
                let src1 = p1 `plusPtr` off1
                let diff = len0 - len1
                copyBytes dst src0 diff
                loop (dst `plusPtr` diff) (src0 `plusPtr` diff) src1 len1
  where
    loop :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Int -> IO ()
    loop _ _ _ 0 = return ()
    loop dst src0 src1 len = do
        w1 <- peek src0
        w2 <- peek src1
        poke dst (w1 `xor` w2)
        loop (dst `plusPtr` 1) (src0 `plusPtr` 1) (src1 `plusPtr` 1) (len - 1)

{-
bsXORpad' :: ByteString -> ByteString -> ByteString
bsXORpad' iv pn = BS.pack $ zipWith xor ivl pnl
  where
    ivl = BS.unpack iv
    diff = BS.length iv - BS.length pn
    pnl = replicate diff 0 ++ BS.unpack pn
-}

----------------------------------------------------------------

type NiteEncrypt = Buffer -> PlainText -> AssDat -> PacketNumber -> IO Int

makeNiteEncrypt :: Cipher -> Key -> IV -> NiteEncrypt
makeNiteEncrypt cipher key iv = niteEncryptWrapper (niteEncrypt cipher key iv)

niteEncryptWrapper
    :: (PlainText -> AssDat -> PacketNumber -> Maybe (CipherText, CipherText))
    -> NiteEncrypt
niteEncryptWrapper enc dst plaintext ad pn = case enc plaintext ad pn of
    Nothing -> return (-1)
    Just (hdr, bdy) -> do
        len <- copyBS dst hdr
        let dst' = dst `plusPtr` len
        len' <- copyBS dst' bdy
        return (len + len')

niteEncrypt
    :: Cipher
    -> Key
    -> IV
    -> PlainText
    -> AssDat
    -> PacketNumber
    -> Maybe (CipherText, CipherText)
niteEncrypt cipher key iv =
    let enc = cipherEncrypt cipher key
        mk = makeNonce iv
     in \plaintext header pn ->
            let bytePN = bytestring64 $ fromIntegral pn
                nonce = mk bytePN
             in enc nonce plaintext header

niteEncrypt'
    :: Cipher -> Key -> Nonce -> PlainText -> AssDat -> Maybe (CipherText, CipherText)
niteEncrypt' cipher key nonce plaintext header =
    cipherEncrypt cipher key nonce plaintext header

----------------------------------------------------------------

type NiteDecrypt = Buffer -> CipherText -> AssDat -> PacketNumber -> IO Int

makeNiteDecrypt :: Cipher -> Key -> IV -> NiteDecrypt
makeNiteDecrypt cipher key iv = niteDecryptWrapper (niteDecrypt cipher key iv)

niteDecryptWrapper
    :: (CipherText -> AssDat -> PacketNumber -> Maybe PlainText) -> NiteDecrypt
niteDecryptWrapper dec dst ciphertext ad pn = case dec ciphertext ad pn of
    Nothing -> return (-1)
    Just bs -> copyBS dst bs

niteDecrypt
    :: Cipher
    -> Key
    -> IV
    -> CipherText
    -> AssDat
    -> PacketNumber
    -> Maybe PlainText
niteDecrypt cipher key iv =
    let dec = cipherDecrypt cipher key
        mk = makeNonce iv
     in \ciphertext header pn ->
            let bytePN = bytestring64 (fromIntegral pn)
                nonce = mk bytePN
             in dec nonce ciphertext header

niteDecrypt'
    :: Cipher -> Key -> Nonce -> CipherText -> AssDat -> Maybe PlainText
niteDecrypt' cipher key nonce ciphertext header =
    cipherDecrypt cipher key nonce ciphertext header

----------------------------------------------------------------

protectionMask :: Cipher -> Key -> (Sample -> Mask)
protectionMask cipher key =
    let f = cipherHeaderProtection cipher key
     in \sample -> f sample

cipherHeaderProtection :: Cipher -> Key -> (Sample -> Mask)
cipherHeaderProtection cipher key
    | cipher == cipher13_AES_128_GCM_SHA256 = aes128ecbEncrypt key
    | cipher == cipher13_AES_128_CCM_SHA256 = error "cipher13_AES_128_CCM_SHA256 "
    | cipher == cipher13_AES_256_GCM_SHA384 = aes256ecbEncrypt key
    | cipher == cipher13_CHACHA20_POLY1305_SHA256 = chacha20HeaderProtection key
    | otherwise =
        error "cipherHeaderProtection"

aes128ecbEncrypt :: Key -> (Sample -> Mask)
aes128ecbEncrypt (Key key) = case maybeCryptoError $ cipherInit key of
    Nothing -> \_ -> Mask "0123456789012345"
    Just (aes :: AES128) ->
        let encrypt = ecbEncrypt aes
         in \(Sample sample) ->
                let mask = encrypt sample
                 in Mask mask

aes256ecbEncrypt :: Key -> (Sample -> Mask)
aes256ecbEncrypt (Key key) = case maybeCryptoError $ cipherInit key of
    Nothing -> \_ -> Mask "0123456789012345"
    Just (aes :: AES256) ->
        let encrypt = ecbEncrypt aes
         in \(Sample sample) ->
                let mask = encrypt sample
                 in Mask mask

chacha20HeaderProtection :: Key -> (Sample -> Mask)
chacha20HeaderProtection (Key keyBytes) (Sample sample) =
    -- RFC 9001 §5.4: sample is 16 bytes: 4-byte LE block counter + 12-byte nonce.
    -- We only need first 5 bytes of keystream for that block.
    if BS.length sample < 16 then Mask (BS.replicate 5 0) else
        let (counterBytes, nonceBytes) = BS.splitAt 4 sample
            counter = fromIntegral (BS.index counterBytes 0)
                    .|. (fromIntegral (BS.index counterBytes 1) `shiftL` 8)
                    .|. (fromIntegral (BS.index counterBytes 2) `shiftL` 16)
                    .|. (fromIntegral (BS.index counterBytes 3) `shiftL` 24)
            (maskBytes, _) = chacha20BlockFirstBytes keyBytes nonceBytes counter 5
        in Mask maskBytes

-- Produce first 'n' keystream bytes of the ChaCha20 block for given key (32), nonce (12) and counter.
chacha20BlockFirstBytes :: ByteString -> ByteString -> Word32 -> Int -> (ByteString, ())
chacha20BlockFirstBytes key nonce ctr n = (BS.take n (serialize $ zipWith (+) state working), ())
    where
        state :: [Word32]
        state = constWords ++ keyWords ++ [ctr] ++ nonceWords
        working = doRounds 10 state
        constWords = [0x61707865,0x3320646e,0x79622d32,0x6b206574]
        keyWords   = toWords 8 key
        nonceWords = toWords 3 nonce
        doRounds :: Int -> [Word32] -> [Word32]
        doRounds 0 s = s
        doRounds i s = doRounds (i-1) (diag (cols s))
        cols s = qr 0 4 8 12 (qr 1 5 9 13 (qr 2 6 10 14 (qr 3 7 11 15 s)))
        diag s = qr 0 5 10 15 (qr 1 6 11 12 (qr 2 7 8 13 (qr 3 4 9 14 s)))
        qr a b c d s = replace d d' (replace c c' (replace b b' (replace a a' s)))
            where
                a0 = s !! a; b0 = s !! b; c0 = s !! c; d0 = s !! d
                a1 = a0 + b0; d1 = rotl (d0 `xor` a1) 16
                c1 = c0 + d1; b1 = rotl (b0 `xor` c1) 12
                a2 = a1 + b1; d2 = rotl (d1 `xor` a2) 8
                c2 = c1 + d2; b2 = rotl (b1 `xor` c2) 7
                a' = a2; b' = b2; c' = c2; d' = d2
        rotl w s = (w `shiftL` s) .|. (w `shiftR` (32 - s))
        replace i x s = take i s ++ [x] ++ drop (i+1) s
        serialize = BS.concat . map word32LE
        word32LE w = BS.pack [ fromIntegral (w .&. 0xff)
                                                 , fromIntegral ((w `shiftR` 8) .&. 0xff)
                                                 , fromIntegral ((w `shiftR` 16) .&. 0xff)
                                                 , fromIntegral ((w `shiftR` 24) .&. 0xff) ]
        toWords count bs = map wordLE (take count (chunks bs))
        wordLE bs4 = fromIntegral (BS.index bs4 0)
                            .|. (fromIntegral (BS.index bs4 1) `shiftL` 8)
                            .|. (fromIntegral (BS.index bs4 2) `shiftL` 16)
                            .|. (fromIntegral (BS.index bs4 3) `shiftL` 24)
        chunks b | BS.null b = []
                         | otherwise = let (h,t) = BS.splitAt 4 b in h : chunks t
            

----------------------------------------------------------------

makeNiteProtector :: Cipher -> Key -> IO (Buffer -> IO (), IO Buffer)
makeNiteProtector cipher key = do
    ref <- newIORef nullPtr
    dstbuf <- mallocBytes 32 -- fixme: free
    return (niteSetSample ref, niteGetMask ref samplelen mkMask dstbuf)
  where
    samplelen = 16 -- sampleLength cipher -- fixme
    mkMask = protectionMask cipher key

niteSetSample :: IORef Buffer -> Buffer -> IO ()
niteSetSample = writeIORef

niteGetMask :: IORef Buffer -> Int -> (Sample -> Mask) -> Buffer -> IO Buffer
niteGetMask ref samplelen mkMask dstbuf = do
    srcbuf <- readIORef ref
    sample <- do
        fptr <- newForeignPtr_ srcbuf
        return $ PS fptr 0 samplelen
    let Mask mask = mkMask $ Sample sample
    _len <- copyBS dstbuf mask
    return dstbuf
