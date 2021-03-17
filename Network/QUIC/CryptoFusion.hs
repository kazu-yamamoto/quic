module Network.QUIC.CryptoFusion (
    FusionContext
  , emptyFusionContext
  , fusionNewContext
  , fusionFreeContext
  , fusionSetup
  , fusionDisposeKey
  , fusionEncrypt
  , fusionDecrypt
  , Supplement
  , fusionSetupSupplement
  , fusionFreeSupplement
  , fusionSetSample
  , fusionGetMask
  ) where

import Foreign.C.Types
import Foreign.Ptr
import Network.TLS.Extra.Cipher

import Network.QUIC.Crypto
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

data FusionContextOpaque
type FusionContext = Ptr FusionContextOpaque

fusionNewContext :: IO FusionContext
fusionNewContext = c_aead_context_new

emptyFusionContext :: FusionContext
emptyFusionContext = nullPtr

fusionFreeContext :: FusionContext -> IO ()
fusionFreeContext p
  | p == nullPtr = return ()
  | otherwise    = c_aead_context_free p

----------------------------------------------------------------

fusionSetup :: Cipher -> FusionContext -> Key -> IV -> IO ()
fusionSetup cipher
  | cipher == cipher_TLS13_AES128GCM_SHA256        = fusionSetupAES128
  | cipher == cipher_TLS13_AES256GCM_SHA384        = fusionSetupAES256
  | otherwise                                      = error "fusionSetup"

fusionSetupAES128 :: FusionContext -> Key -> IV -> IO ()
fusionSetupAES128 pctx (Key key) (IV iv) = do
    withByteString key $ \keyp ->
        withByteString iv $ \ivp -> void $ c_aes128gcm_setup pctx 0 keyp ivp

fusionSetupAES256 :: FusionContext -> Key -> IV -> IO ()
fusionSetupAES256 pctx (Key key) (IV iv) = do
    withByteString key $ \keyp ->
        withByteString iv $ \ivp -> void $ c_aes256gcm_setup pctx 0 keyp ivp

----------------------------------------------------------------

fusionDisposeKey :: FusionContext -> IO ()
fusionDisposeKey = c_aesgcm_dispose_crypto

----------------------------------------------------------------

fusionEncrypt :: FusionContext -> Buffer -> Int -> Buffer -> Int -> PacketNumber -> Buffer -> Supplement -> IO Int
fusionEncrypt pctx ibuf ilen abuf alen pn obuf supp = do
    c_aead_do_encrypt pctx obuf ibuf ilen' pn' abuf alen' supp
    return (ilen + 16) -- fixme
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

----------------------------------------------------------------

data SupplementOpaque
type Supplement = Ptr SupplementOpaque

fusionSetupSupplement :: Cipher -> Key -> IO Supplement
fusionSetupSupplement cipher (Key hpkey) =
    withByteString hpkey $ \hpkeyp -> c_supplement_new hpkeyp keylen
 where
  keylen
    | cipher == cipher_TLS13_AES128GCM_SHA256 = 16
    | otherwise                               = 32

fusionFreeSupplement :: Supplement -> IO ()
fusionFreeSupplement p
  | p == nullPtr = return ()
  | otherwise    = c_supplement_free p

fusionSetSample :: Supplement -> Ptr Word8 -> IO ()
fusionSetSample = c_supplement_set_sample

fusionGetMask :: Supplement -> IO (Ptr Word8)
fusionGetMask   = c_supplement_get_mask

----------------------------------------------------------------

foreign import ccall unsafe "aead_context_new"
    c_aead_context_new :: IO FusionContext

foreign import ccall unsafe "aead_context_free"
    c_aead_context_free :: FusionContext -> IO ()

foreign import ccall unsafe "aes128gcm_setup"
    c_aes128gcm_setup :: FusionContext
                      -> CInt       -- dummy
                      -> Ptr Word8  -- key
                      -> Ptr Word8  -- iv
                      -> IO CInt

foreign import ccall unsafe "aes256gcm_setup"
    c_aes256gcm_setup :: FusionContext
                      -> CInt       -- dummy
                      -> Ptr Word8  -- key
                      -> Ptr Word8  -- iv
                      -> IO CInt

foreign import ccall unsafe "aesgcm_dispose_crypto"
    c_aesgcm_dispose_crypto :: FusionContext -> IO ()

foreign import ccall unsafe "aead_do_encrypt"
    c_aead_do_encrypt :: FusionContext
                      -> Ptr Word8 -- output
                      -> Ptr Word8 -- input
                      -> CSize     -- input length
                      -> CULong    -- sequence
                      -> Ptr Word8 -- AAD
                      -> CSize     -- AAD length
                      -> Supplement
                      -> IO ()

foreign import ccall unsafe "aead_do_decrypt"
    c_aead_do_decrypt :: FusionContext
                      -> Ptr Word8 -- output
                      -> Ptr Word8 -- input
                      -> CSize     -- input length
                      -> CULong    -- sequence
                      -> Ptr Word8 -- AAD
                      -> CSize     -- AAD length
                      -> IO CSize

foreign import ccall unsafe "supplement_new"
    c_supplement_new :: Ptr Word8 -> CInt -> IO Supplement

foreign import ccall unsafe "supplement_free"
    c_supplement_free :: Supplement -> IO ()

foreign import ccall unsafe "supplement_set_sample"
    c_supplement_set_sample :: Supplement -> Ptr Word8 -> IO ()

foreign import ccall unsafe "supplement_get_mask"
    c_supplement_get_mask :: Supplement -> IO (Ptr Word8)
