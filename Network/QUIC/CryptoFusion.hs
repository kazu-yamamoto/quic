module Network.QUIC.CryptoFusion where

import qualified Data.ByteString as BS
import Data.ByteString.Internal
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr

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

withByteString :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteString (PS fptr off _) f = withForeignPtr fptr $ \ptr ->
  f (ptr `plusPtr` off)

fusionSetupAES128GCM :: FusionContext -> Key -> IV -> IO ()
fusionSetupAES128GCM pctx (Key key) (IV iv) =
    withByteString key $ \keyp ->
        withByteString iv $ \ivp -> void $ c_aes128gcm_setup pctx 0 keyp ivp

fusionSetupAES256GCM :: FusionContext -> Key -> IV -> IO ()
fusionSetupAES256GCM pctx (Key key) (IV iv) =
    withByteString key $ \keyp ->
        withByteString iv $ \ivp -> void $ c_aes256gcm_setup pctx 0 keyp ivp

fusionEncrypt :: FusionContext -> PlainText -> AddDat -> PacketNumber -> Buffer -> IO ()
fusionEncrypt pctx inp (AddDat add) pn buf = do
    let ilen = fromIntegral $ BS.length inp
        alen = fromIntegral $ BS.length add
        pn'  = fromIntegral pn
    withByteString inp $ \inpp -> withByteString add $ \addp ->
      c_aead_do_encrypt pctx buf inpp ilen pn' addp alen nullPtr

fusionDecrypt :: FusionContext -> CipherText -> AddDat -> PacketNumber -> Buffer -> IO Int
fusionDecrypt pctx inp (AddDat add) pn buf = do
    let ilen = fromIntegral $ BS.length inp
        alen = fromIntegral $ BS.length add
        pn'  = fromIntegral pn
    withByteString inp $ \inpp -> withByteString add $ \addp ->
      fromIntegral <$> c_aead_do_decrypt pctx buf inpp ilen pn' addp alen
