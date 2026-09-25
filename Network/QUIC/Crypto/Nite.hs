{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.QUIC.Crypto.Nite (
    supportedCipher,
    unsupportedCipher,
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
    makeGcmEncrypt,
    makeGcmDecrypt,
) where

import Crypto.Cipher.AES
import qualified Crypto.Cipher.AES.GCM as GCM
import qualified Crypto.Cipher.ChaCha as ChaCha
import Crypto.Cipher.ChaChaPoly1305 (aeadChacha20poly1305Init)
import Crypto.Cipher.Types hiding (Cipher, IV)
import Crypto.Error (maybeCryptoError)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import qualified Data.ByteArray as Byte (ByteArrayAccess (..), convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import Foreign.ForeignPtr (ForeignPtr, mallocForeignPtrBytes, newForeignPtr_, withForeignPtr)
import Foreign.Marshal.Alloc (mallocBytes)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, minusPtr, nullPtr, plusPtr)
import Foreign.Storable (peek, poke, pokeByteOff)
import Foreign.Ptr (castPtr)
import Network.TLS hiding (Version)
import qualified Network.TLS as TLS
import Network.TLS.Extra.Cipher

import Network.QUIC.Crypto.Types
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

-- | The ciphers this implements.
--
-- AES-128-CCM is a TLS 1.3 cipher suite and is deliberately not here: there
-- is no CCM in cipherEncrypt or cipherDecrypt.  It used to be accepted by the
-- two length functions below, so configuring it got past them and failed
-- later, inside encryption, with nothing to say which cipher it meant.
supportedCipher :: Cipher -> Bool
supportedCipher cipher =
    cipher
        `elem` [ cipher13_AES_128_GCM_SHA256
               , cipher13_AES_256_GCM_SHA384
               , cipher13_CHACHA20_POLY1305_SHA256
               ]

unsupportedCipher :: String -> Cipher -> a
unsupportedCipher fun cipher =
    error $ fun ++ ": unsupported cipher " ++ show (TLS.cipherName cipher)

-- It would be nice to take [PlainText] and update AEAD context with
-- [PlainText]. But since each PlainText is not aligned to cipher block,
-- it's impossible.
cipherEncrypt
    :: Cipher -> Key -> Nonce -> PlainText -> AssDat -> Maybe (CipherText, CipherText)
cipherEncrypt cipher key@(Key key') (Nonce nonce)
    | cipher == cipher13_AES_128_GCM_SHA256 =
        quicAeadEncrypt (aesGCMInit key nonce :: Maybe (AEAD AES128)) 16
    | cipher == cipher13_AES_256_GCM_SHA384 =
        quicAeadEncrypt (aesGCMInit key nonce :: Maybe (AEAD AES256)) 16
    | cipher == cipher13_CHACHA20_POLY1305_SHA256 =
        quicAeadEncrypt (maybeCryptoError $ aeadChacha20poly1305Init key' nonce) 16
    | otherwise = unsupportedCipher "cipherEncrypt" cipher

cipherDecrypt
    :: Cipher -> Key -> Nonce -> CipherText -> AssDat -> Maybe PlainText
cipherDecrypt cipher key@(Key key') (Nonce nonce)
    | cipher == cipher13_AES_128_GCM_SHA256 =
        quicAeadDecrypt (aesGCMInit key nonce :: Maybe (AEAD AES128)) 16
    | cipher == cipher13_AES_256_GCM_SHA384 =
        quicAeadDecrypt (aesGCMInit key nonce :: Maybe (AEAD AES256)) 16
    | cipher == cipher13_CHACHA20_POLY1305_SHA256 =
        quicAeadDecrypt (maybeCryptoError $ aeadChacha20poly1305Init key' nonce) 16
    | otherwise = unsupportedCipher "cipherDecrypt" cipher

-- IMPORTANT: Using 'let' so that parameters can be memorized.
quicAeadEncrypt
    :: Maybe (AEAD cipher)
    -> Int
    -> PlainText
    -> AssDat
    -> Maybe (CipherText, CipherText)
quicAeadEncrypt Nothing _ = \_ _ -> Nothing
quicAeadEncrypt (Just aead) tagLen = \plaintext (AssDat ad) ->
    let (AuthTag tag0, ciphertext) = aeadSimpleEncrypt aead ad plaintext tagLen
        tag = Byte.convert tag0
     in Just (ciphertext, tag)

quicAeadDecrypt
    :: Maybe (AEAD cipher) -> Int -> CipherText -> AssDat -> Maybe PlainText
quicAeadDecrypt Nothing _ = \_ _ -> Nothing
quicAeadDecrypt (Just aead) tagLen = \ciphertag (AssDat ad) ->
    let (ciphertext, tag) = BS.splitAt (BS.length ciphertag - tagLen) ciphertag
        authtag = AuthTag $ Byte.convert tag
     in aeadSimpleDecrypt aead ad ciphertext authtag

aesGCMInit
    :: BlockCipher cipher => Key -> ByteString -> Maybe (AEAD cipher)
aesGCMInit (Key key) nonce =
    case maybeCryptoError $ cipherInit key of
        Nothing -> Nothing
        Just aes -> maybeCryptoError $ aeadInit AEAD_GCM aes nonce

aes128gcmEncrypt
    :: Key -> Nonce -> PlainText -> AssDat -> Maybe (CipherText, CipherText)
aes128gcmEncrypt key (Nonce nonce) =
    quicAeadEncrypt (aesGCMInit key nonce :: Maybe (AEAD AES128)) 16

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
    | cipher == cipher13_AES_256_GCM_SHA384 = aes256ecbEncrypt key
    | cipher == cipher13_CHACHA20_POLY1305_SHA256 = chacha20HeaderProtection key
    | otherwise = unsupportedCipher "cipherHeaderProtection" cipher

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
chacha20HeaderProtection (Key key) (Sample sample) =
    Mask $ fst $ ChaCha.combine st "\x00\x00\x00\x00\x00"
  where
    st = ChaCha.setCounter32 counter $ ChaCha.initialize 20 key nonce
    nonce = BS.drop 4 sample
    counter = idx 0 + idx 1 * 256 + idx 2 * 65536 + idx 3 * 16777216
    idx i = fromIntegral (sample `BS.index` i)

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

----------------------------------------------------------------

{-
 - AES-GCM through crypton's one-call interface.
 -
 - What the interface above this costs is not the encryption.  A t'Context'
 - is built from the key once, where 'aeadInit' rebuilt the key schedule and
 - the table of multiples of H for every nonce; and the header protection
 - mask comes back from the same call as the ciphertext, riding in a lane of
 - the AES pipeline that the packet length leaves idle, where it used to be a
 - block of its own after the fact.
 -
 - The sample offset the mask is taken from is not fixed: QUIC samples four
 - bytes past the start of the packet number, and the ciphertext starts after
 - it, so the offset is four less the length of the encoded packet number.
 - 'setSample' is handed the address, and the offset is what it is from the
 - output buffer the encryption is given.
 -}

{-
 - The nonce, written into a buffer the connection keeps rather than built
 - fresh.  It is the IV with the packet number exclusive-ored into its low
 - eight bytes, and the obvious way -- bytestring64 and bsXORpad -- allocates
 - two ByteStrings for every packet.  At these lengths that is a third of
 - what the encryption costs.
 -}
newtype NoncePtr = NoncePtr (ForeignPtr Word8)

instance Byte.ByteArrayAccess NoncePtr where
    length _ = 12
    withByteArray (NoncePtr fp) f = withForeignPtr fp (f . castPtr)

writeNonce :: Ptr Word8 -> Ptr Word8 -> Word64 -> IO ()
writeNonce dst ivp pn = do
    copyBytes dst ivp 4
    go 0
  where
    go :: Int -> IO ()
    go 8 = return ()
    go j = do
        b <- peek (ivp `plusPtr` (4 + j)) :: IO Word8
        pokeByteOff dst (4 + j) (b `xor` fromIntegral (pn `shiftR` (56 - 8 * j)))
        go (j + 1)

-- | Whether this is one of the two AES-GCM suites, which is what the
-- interface below covers.  ChaCha20-Poly1305 has no equivalent there and
-- stays with the code above.
gcmKeySize :: Cipher -> Maybe Int
gcmKeySize cipher
    | cipher == cipher13_AES_128_GCM_SHA256 = Just 16
    | cipher == cipher13_AES_256_GCM_SHA384 = Just 32
    | otherwise = Nothing

-- | The encryption side, with the mask.  The two extra actions are the
-- 'Protector' halves: they and the encryption share the buffer the mask is
-- written to and the address the sample is taken from.
makeGcmEncrypt
    :: Cipher
    -> Key
    -> IV
    -> Key
    -> IO (Maybe (NiteEncrypt, Buffer -> IO (), IO Buffer))
makeGcmEncrypt cipher (Key key) iv (Key hpkey) = case gcmKeySize cipher of
    Nothing -> return Nothing
    Just _ -> case (mctx, mhk) of
        (Just ctx, Just hk) -> do
            ref <- newIORef nullPtr
            maskBuf <- mallocBytes 16 -- fixme: free
            ivfp <- mallocForeignPtrBytes 12
            noncefp <- mallocForeignPtrBytes 12
            let IV ivbs = iv
            withForeignPtr ivfp $ \p -> void $ copyBS p ivbs
            let enc dst plaintext (AssDat ad) pn = do
                    sample <- readIORef ref
                    let off = sample `minusPtr` dst
                    withForeignPtr noncefp $ \np ->
                        withForeignPtr ivfp $ \ivp ->
                            writeNonce np ivp (fromIntegral pn)
                    ok <-
                        GCM.encryptWithMask
                            ctx
                            hk
                            (NoncePtr noncefp)
                            ad
                            plaintext
                            16
                            off
                            dst
                            maskBuf
                    return $ if ok then BS.length plaintext + 16 else -1
            return $ Just (enc, writeIORef ref, return maskBuf)
        _ -> return Nothing
  where
    mctx = maybeCryptoError $ GCM.newContext key
    mhk = maybeCryptoError $ GCM.newHeaderKey hpkey

-- | The decryption side.  There is no mask here: the receiver takes its
-- sample from the packet it was given, before anything is decrypted.
makeGcmDecrypt :: Cipher -> Key -> IV -> Maybe NiteDecrypt
makeGcmDecrypt cipher (Key key) iv = case gcmKeySize cipher of
    Nothing -> Nothing
    Just _ -> case maybeCryptoError $ GCM.newContext key of
        Nothing -> Nothing
        Just ctx ->
            let mk = makeNonce iv
                dec dst ciphertext (AssDat ad) pn =
                    let Nonce nonce = mk $ bytestring64 $ fromIntegral pn
                     in case GCM.decrypt ctx nonce ad ciphertext 16 of
                            Nothing -> return (-1)
                            Just plain -> copyBS dst plain
             in Just dec
