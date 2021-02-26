module Network.QUIC.CryptoFusion where

import Foreign.C.Types
import Foreign.Ptr
import Network.QUIC.Imports

data FusionContext

-- ptls_aead_context_t --> malloc(sizeof(struct aesgcm_context))

foreign import ccall unsafe "aead_context_new"
    fusionNewContext :: IO (Ptr FusionContext)

-- static int aes128gcm_setup(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)

foreign import ccall unsafe "aes128gcm_setup"
    fusionSetupAES128GCM :: Ptr FusionContext
                         -> CInt       -- dummy
                         -> Ptr Word8  -- key
                         -> Ptr Word8  -- iv
                         -> IO CInt

-- static int aes256gcm_setup(ptls_aead_context_t *ctx, int is_enc, const void *key, const void *iv)

foreign import ccall unsafe "aes256gcm_setup"
    fusionSetupAES256GCM :: Ptr FusionContext
                         -> CInt       -- dummy
                         -> Ptr Word8  -- key
                         -> Ptr Word8  -- iv
                         -> IO CInt

-- aesgcm_dispose_crypto(ptls_aead_context_t *_ctx)

foreign import ccall unsafe "aesgcm_dispose_crypto"
    fusionDisposeKey :: Ptr FusionContext -> IO ()

-- void aead_do_encrypt(struct st_ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq, const void *aad, size_t aadlen, ptls_aead_supplementary_encryption_t *supp)

foreign import ccall unsafe "aead_do_encrypt"
    fusionEncrypt :: Ptr FusionContext
                  -> Ptr Word8 -- output
                  -> Ptr Word8 -- input
                  -> CSize     -- input length
                  -> CULong    -- sequence
                  -> Ptr Word8 -- AAD
                  -> CSize     -- AAD length
                  -> Ptr Word8 -- supplementary
                  -> IO ()

-- static size_t aead_do_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq, const void *aad, size_t aadlen)

foreign import ccall unsafe "aead_do_decrypt"
    fusionDecrypt :: Ptr FusionContext
                  -> Ptr Word8 -- output
                  -> Ptr Word8 -- input
                  -> CSize     -- input length
                  -> CULong    -- sequence
                  -> Ptr Word8 -- AAD
                  -> CSize     -- AAD length
                  -> IO ()
