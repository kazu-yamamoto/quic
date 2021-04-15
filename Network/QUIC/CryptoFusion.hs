module Network.QUIC.CryptoFusion (
    FusionContext
  , fusionNewContext
  , fusionSetup
  , fusionEncrypt
  , fusionDecrypt
  , Supplement
  , fusionSetupSupplement
  , fusionSetSample
  , fusionGetMask
  ) where

import Foreign.C.Types
import Foreign.Ptr
import Foreign.ForeignPtr
import Network.TLS.Extra.Cipher

import Network.QUIC.Crypto
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

data FusionContextOpaque
newtype FusionContext = FC (ForeignPtr FusionContextOpaque)

fusionNewContext :: IO FusionContext
fusionNewContext = FC <$> (c_aead_context_new >>= newForeignPtr p_aead_context_free)

----------------------------------------------------------------

fusionSetup :: Cipher -> FusionContext -> Key -> IV -> IO ()
fusionSetup cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = fusionSetupAES128
  | cipher == cipher_TLS13_AES256GCM_SHA384        = fusionSetupAES256
  | otherwise                                      = error "fusionSetup"

fusionSetupAES128 :: FusionContext -> Key -> IV -> IO ()
fusionSetupAES128 (FC fctx) (Key key) (IV iv) = withForeignPtr fctx $ \pctx ->
    withByteString key $ \keyp ->
        withByteString iv $ \ivp -> void $ c_aes128gcm_setup pctx 0 keyp ivp

fusionSetupAES256 :: FusionContext -> Key -> IV -> IO ()
fusionSetupAES256 (FC fctx) (Key key) (IV iv) = withForeignPtr fctx $ \pctx ->
    withByteString key $ \keyp ->
        withByteString iv $ \ivp -> void $ c_aes256gcm_setup pctx 0 keyp ivp

----------------------------------------------------------------

fusionEncrypt :: FusionContext -> Supplement -> Buffer -> Int -> Buffer -> Int -> PacketNumber -> Buffer -> IO Int
fusionEncrypt (FC fctx) (SP fsupp) ibuf ilen abuf alen pn obuf =
    withForeignPtr fctx $ \pctx -> withForeignPtr fsupp $ \psupp -> do
        c_aead_do_encrypt pctx obuf ibuf ilen' pn' abuf alen' psupp
        return (ilen + 16) -- fixme
  where
    pn' = fromIntegral pn
    ilen' = fromIntegral ilen
    alen' = fromIntegral alen

fusionDecrypt :: FusionContext -> Buffer -> Int -> Buffer -> Int -> PacketNumber -> Buffer -> IO Int
fusionDecrypt (FC fctx) ibuf ilen abuf alen pn buf =
    withForeignPtr fctx $ \pctx ->
        fromIntegral <$> c_aead_do_decrypt pctx buf ibuf ilen' pn' abuf alen'
  where
    pn' = fromIntegral pn
    ilen' = fromIntegral ilen
    alen' = fromIntegral alen

----------------------------------------------------------------

data SupplementOpaque
newtype Supplement = SP (ForeignPtr SupplementOpaque)

fusionSetupSupplement :: Cipher -> Key -> IO Supplement
fusionSetupSupplement cipher (Key hpkey) = withByteString hpkey $ \hpkeyp ->
  SP <$> (c_supplement_new hpkeyp keylen >>= newForeignPtr p_supplement_free)
 where
  keylen
    | cipher == cipher_TLS13_AES128GCM_SHA256 = 16
    | otherwise                               = 32

fusionSetSample :: Supplement -> Ptr Word8 -> IO ()
fusionSetSample (SP fsupp) p = withForeignPtr fsupp $ \psupp ->
  c_supplement_set_sample psupp p

fusionGetMask :: Supplement -> IO (Ptr Word8)
fusionGetMask (SP fsupp) = withForeignPtr fsupp c_supplement_get_mask

----------------------------------------------------------------

foreign import ccall unsafe "aead_context_new"
    c_aead_context_new :: IO (Ptr FusionContextOpaque)

foreign import ccall unsafe "&aead_context_free"
    p_aead_context_free :: FunPtr (Ptr FusionContextOpaque -> IO ())

foreign import ccall unsafe "aes128gcm_setup"
    c_aes128gcm_setup :: Ptr FusionContextOpaque
                      -> CInt       -- dummy
                      -> Ptr Word8  -- key
                      -> Ptr Word8  -- iv
                      -> IO CInt

foreign import ccall unsafe "aes256gcm_setup"
    c_aes256gcm_setup :: Ptr FusionContextOpaque
                      -> CInt       -- dummy
                      -> Ptr Word8  -- key
                      -> Ptr Word8  -- iv
                      -> IO CInt
{-
foreign import ccall unsafe "aesgcm_dispose_crypto"
    c_aesgcm_dispose_crypto :: FusionContext -> IO ()
-}

foreign import ccall unsafe "aead_do_encrypt"
    c_aead_do_encrypt :: Ptr FusionContextOpaque
                      -> Ptr Word8 -- output
                      -> Ptr Word8 -- input
                      -> CSize     -- input length
                      -> CULong    -- sequence
                      -> Ptr Word8 -- AAD
                      -> CSize     -- AAD length
                      -> Ptr SupplementOpaque
                      -> IO ()

foreign import ccall unsafe "aead_do_decrypt"
    c_aead_do_decrypt :: Ptr FusionContextOpaque
                      -> Ptr Word8 -- output
                      -> Ptr Word8 -- input
                      -> CSize     -- input length
                      -> CULong    -- sequence
                      -> Ptr Word8 -- AAD
                      -> CSize     -- AAD length
                      -> IO CSize

foreign import ccall unsafe "supplement_new"
    c_supplement_new :: Ptr Word8 -> CInt -> IO (Ptr SupplementOpaque)

foreign import ccall unsafe "&supplement_free"
    p_supplement_free :: FunPtr (Ptr SupplementOpaque -> IO ())

foreign import ccall unsafe "supplement_set_sample"
    c_supplement_set_sample :: Ptr SupplementOpaque -> Ptr Word8 -> IO ()

foreign import ccall unsafe "supplement_get_mask"
    c_supplement_get_mask :: Ptr SupplementOpaque -> IO (Ptr Word8)
