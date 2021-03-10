module Network.QUIC.CryptoFusion (
    FusionContext
  , emptyFusionContext
  , fusionSetup
  , fusionNewContext
  , fusionDisposeKey
  , fusionEncrypt
  , fusionDecrypt
  ) where

import Foreign.C.Types
import Foreign.Ptr
import Network.TLS.Extra.Cipher

import Network.QUIC.Crypto
import Network.QUIC.Imports
import Network.QUIC.Types

data FusionContextOpaque
type FusionContext = Ptr FusionContextOpaque

-- ptls_aead_context_t --> malloc(sizeof(struct aesgcm_context))

foreign import ccall unsafe "aead_context_new"
    fusionNewContext :: IO FusionContext

-- static int aes128gcm_setup(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)

foreign import ccall unsafe "aes128gcm_setup"
    c_aes128gcm_setup :: FusionContext
                      -> CInt       -- dummy
                      -> Ptr Word8  -- key
                      -> Ptr Word8  -- iv
                      -> IO CInt

-- static int aes256gcm_setup(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)

foreign import ccall unsafe "aes256gcm_setup"
    c_aes256gcm_setup :: FusionContext
                      -> CInt       -- dummy
                      -> Ptr Word8  -- key
                      -> Ptr Word8  -- iv
                      -> IO CInt

-- aesgcm_dispose_crypto(ptls_aead_context_t *_ctx)

foreign import ccall unsafe "aesgcm_dispose_crypto"
    fusionDisposeKey :: FusionContext -> IO ()

-- void aead_do_encrypt(struct st_ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq, const void *aad, size_t aadlen, ptls_aead_supplementary_encryption_t *supp)

foreign import ccall unsafe "aead_do_encrypt"
    c_aead_do_encrypt :: FusionContext
                      -> Ptr Word8 -- output
                      -> Ptr Word8 -- input
                      -> CSize     -- input length
                      -> CULong    -- sequence
                      -> Ptr Word8 -- AAD
                      -> CSize     -- AAD length
                      -> Ptr Word8 -- supplementary
                      -> IO ()

-- size_t aead_do_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq, const void *aad, size_t aadlen)

foreign import ccall unsafe "aead_do_decrypt"
    c_aead_do_decrypt :: FusionContext
                  -> Ptr Word8 -- output
                  -> Ptr Word8 -- input
                  -> CSize     -- input length
                  -> CULong    -- sequence
                  -> Ptr Word8 -- AAD
                  -> CSize     -- AAD length
                  -> IO CSize

fusionSetup :: Cipher -> FusionContext -> Key -> IV -> IO ()
fusionSetup cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = fusionSetupAES128GCM
  | cipher == cipher_TLS13_AES256GCM_SHA384        = fusionSetupAES256GCM
  | otherwise                                      = error "fusionSetup"

fusionSetupAES128GCM :: FusionContext -> Key -> IV -> IO ()
fusionSetupAES128GCM pctx (Key key) (IV iv) =
    withByteString key $ \keyp ->
        withByteString iv $ \ivp -> void $ c_aes128gcm_setup pctx 0 keyp ivp

fusionSetupAES256GCM :: FusionContext -> Key -> IV -> IO ()
fusionSetupAES256GCM pctx (Key key) (IV iv) =
    withByteString key $ \keyp ->
        withByteString iv $ \ivp -> void $ c_aes256gcm_setup pctx 0 keyp ivp

fusionEncrypt :: FusionContext -> Buffer -> Int -> Buffer -> Int -> PacketNumber -> Buffer -> IO ()
fusionEncrypt pctx ibuf ilen abuf alen pn obuf =
    c_aead_do_encrypt pctx obuf ibuf ilen' pn' abuf alen' nullPtr
  where
    pn' = fromIntegral pn
    ilen' = fromIntegral ilen
    alen' = fromIntegral alen

fusionDecrypt :: FusionContext -> Buffer -> Int -> Buffer -> Int -> PacketNumber -> Buffer -> IO Int
fusionDecrypt pctx ibuf ilen abuf alen pn buf =
    fromIntegral <$> c_aead_do_decrypt pctx buf ibuf ilen' pn' abuf alen'
  where
    pn' = fromIntegral pn
    ilen' = fromIntegral ilen
    alen' = fromIntegral alen

emptyFusionContext :: FusionContext
emptyFusionContext = nullPtr
