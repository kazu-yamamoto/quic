{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Connection.Crypto (
    setEncryptionLevel
  , waitEncryptionLevel
  , putOffCrypto
  --
  , getCipher
  , setCipher
  , getTLSMode
  , getApplicationProtocol
  , setNegotiated
  --
  , dropSecrets
  --
  , initializeCoder
  , initializeCoder1RTT
  , updateCoder1RTT
  , getCoder
  , getProtector
  --
  , getCurrentKeyPhase
  , setCurrentKeyPhase
  ) where

import Control.Concurrent.STM
import Network.TLS.QUIC

import Network.QUIC.Connection.Misc
import Network.QUIC.Connection.Types
import Network.QUIC.Connector
import Network.QUIC.Crypto
import Network.QUIC.Imports
import Network.QUIC.Types

----------------------------------------------------------------

setEncryptionLevel :: Connection -> EncryptionLevel -> IO ()
setEncryptionLevel Connection{..} lvl = do
    let q = connRecvQ
    atomically $ do
        writeTVar (encryptionLevel connState) lvl
        case lvl of
          HandshakeLevel -> do
              readTVar (pendingQ ! RTT0Level)      >>= mapM_ (prependRecvQ q)
              readTVar (pendingQ ! HandshakeLevel) >>= mapM_ (prependRecvQ q)
          RTT1Level      ->
              readTVar (pendingQ ! RTT1Level)      >>= mapM_ (prependRecvQ q)
          _              -> return ()

putOffCrypto :: Connection -> EncryptionLevel -> ReceivedPacket -> IO ()
putOffCrypto Connection{..} lvl rpkt =
    atomically $ modifyTVar' (pendingQ ! lvl) (rpkt :)

waitEncryptionLevel :: Connection -> EncryptionLevel -> IO ()
waitEncryptionLevel Connection{..} lvl = atomically $ do
    l <- readTVar $ encryptionLevel connState
    check (l >= lvl)

----------------------------------------------------------------

getCipher :: Connection -> EncryptionLevel -> IO Cipher
getCipher Connection{..} lvl = readArray ciphers lvl

setCipher :: Connection -> EncryptionLevel -> Cipher -> IO ()
setCipher Connection{..} lvl cipher = writeArray ciphers lvl cipher

----------------------------------------------------------------

getTLSMode :: Connection -> IO HandshakeMode13
getTLSMode Connection{..} = tlsHandshakeMode <$> readIORef negotiated

getApplicationProtocol :: Connection -> IO (Maybe NegotiatedProtocol)
getApplicationProtocol Connection{..} = applicationProtocol <$> readIORef negotiated

setNegotiated :: Connection -> HandshakeMode13 -> Maybe NegotiatedProtocol -> ApplicationSecretInfo -> IO ()
setNegotiated Connection{..} mode mproto appSecInf =
    writeIORef negotiated Negotiated {
        tlsHandshakeMode = mode
      , applicationProtocol = mproto
      , applicationSecretInfo = appSecInf
      }

----------------------------------------------------------------

dropSecrets :: Connection -> EncryptionLevel -> IO ()
dropSecrets Connection{..} lvl = do
    writeArray coders lvl initialCoderFusion
    writeArray protectors lvl initialProtector

----------------------------------------------------------------

initializeCoder :: Connection -> EncryptionLevel -> TrafficSecrets a -> IO ()
initializeCoder conn lvl sec = do
    ver <- if lvl == RTT0Level then
             return $ getOriginalVersion conn
           else
             getVersion conn
    cipher <- getCipher conn lvl
    (coder, protector, _) <-
        if True then
          genFusionCoder (isClient conn) ver cipher sec
        else
          genNiteCoder (isClient conn) ver cipher sec
    writeArray (coders conn) lvl coder
    writeArray (protectors conn) lvl protector

initializeCoder1RTT :: Connection -> TrafficSecrets ApplicationSecret -> IO ()
initializeCoder1RTT conn sec = do
    ver <- getVersion conn
    cipher <- getCipher conn RTT1Level
    (coder, protector, supp) <-
        if True then
          genFusionCoder (isClient conn) ver cipher sec
        else
          genNiteCoder (isClient conn) ver cipher sec
    let coder1 = Coder1RTT coder sec supp
    writeArray (coders1RTT conn) False coder1
    writeArray (protectors conn) RTT1Level protector
    updateCoder1RTT conn True

updateCoder1RTT :: Connection -> Bool -> IO ()
updateCoder1RTT conn nextPhase = do
    ver <- getVersion conn
    cipher <- getCipher conn RTT1Level
    Coder1RTT _ secN supp <- readArray (coders1RTT conn) (not nextPhase)
    let secN1 = updateSecret ver cipher secN
    coderN1 <- genCoder1RTT (isClient conn) ver cipher secN1 supp
    let nextCoder = Coder1RTT coderN1 secN1 supp
    writeArray (coders1RTT conn) nextPhase nextCoder

updateSecret :: Version -> Cipher -> TrafficSecrets ApplicationSecret -> TrafficSecrets ApplicationSecret
updateSecret ver cipher (ClientTrafficSecret cN, ServerTrafficSecret sN) = secN1
  where
    Secret cN1 = nextSecret ver cipher $ Secret cN
    Secret sN1 = nextSecret ver cipher $ Secret sN
    secN1 = (ClientTrafficSecret cN1, ServerTrafficSecret sN1)

genFusionCoder :: Bool -> Version -> Cipher -> TrafficSecrets a -> IO (Coder, Protector, Supplement)
genFusionCoder cli ver cipher (ClientTrafficSecret c, ServerTrafficSecret s) = do
    fctxt <- fusionNewContext
    fctxr <- fusionNewContext
    fusionSetup cipher fctxt txPayloadKey txPayloadIV
    fusionSetup cipher fctxr rxPayloadKey rxPayloadIV
    supp <- fusionSetupSupplement cipher txHeaderKey
    let enc = FusionEncrypt (fusionEncrypt fctxt supp) (fusionSetSample supp) (fusionGetMask supp)
        dec = FusionDecrypt fctxr
        coder = Coder enc dec
    let protector = Protector unp
    return (coder, protector, supp)
  where
    txSecret | cli           = Secret c
             | otherwise     = Secret s
    rxSecret | cli           = Secret s
             | otherwise     = Secret c
    txPayloadKey = aeadKey ver cipher txSecret
    txPayloadIV  = initialVector ver cipher txSecret
    txHeaderKey  = headerProtectionKey ver cipher txSecret
    rxPayloadKey = aeadKey ver cipher rxSecret
    rxPayloadIV  = initialVector ver cipher rxSecret
    rxHeaderKey  = headerProtectionKey ver cipher rxSecret
    unp = protectionMask cipher rxHeaderKey

genNiteCoder :: Bool -> Version -> Cipher -> TrafficSecrets a -> IO (Coder, Protector, Supplement)
genNiteCoder cli ver cipher (ClientTrafficSecret c, ServerTrafficSecret s) = do
    fctxt <- fusionNewContext
    fusionSetup cipher fctxt txPayloadKey txPayloadIV
    supp <- fusionSetupSupplement cipher txHeaderKey
    let enc = FusionEncrypt (fusionEncrypt fctxt supp) (fusionSetSample supp) (fusionGetMask supp)
        dec = niteDecrypt cipher rxPayloadKey rxPayloadIV
        coder = Coder enc (NiteDecrypt dec)
    let protector = Protector unp
    return (coder, protector, supp)
  where
    txSecret | cli           = Secret c
             | otherwise     = Secret s
    rxSecret | cli           = Secret s
             | otherwise     = Secret c
    txPayloadKey = aeadKey ver cipher txSecret
    txPayloadIV  = initialVector ver cipher txSecret
    txHeaderKey  = headerProtectionKey ver cipher txSecret
    rxPayloadKey = aeadKey ver cipher rxSecret
    rxPayloadIV  = initialVector ver cipher rxSecret
    rxHeaderKey  = headerProtectionKey ver cipher rxSecret
    unp = protectionMask cipher rxHeaderKey

genCoder1RTT :: Bool -> Version -> Cipher -> TrafficSecrets a -> Supplement -> IO Coder
genCoder1RTT cli ver cipher (ClientTrafficSecret c, ServerTrafficSecret s) supp = do
    fctxt <- fusionNewContext
    fctxr <- fusionNewContext
    fusionSetup cipher fctxt txPayloadKey txPayloadIV
    fusionSetup cipher fctxr rxPayloadKey rxPayloadIV
    let enc = FusionEncrypt (fusionEncrypt fctxt supp) (fusionSetSample supp) (fusionGetMask supp)
        dec = FusionDecrypt fctxr
        coder = Coder enc dec
    return coder
  where
    txSecret | cli           = Secret c
             | otherwise     = Secret s
    rxSecret | cli           = Secret s
             | otherwise     = Secret c
    txPayloadKey = aeadKey ver cipher txSecret
    txPayloadIV  = initialVector ver cipher txSecret
    rxPayloadKey = aeadKey ver cipher rxSecret
    rxPayloadIV  = initialVector ver cipher rxSecret

getCoder :: Connection -> EncryptionLevel -> Bool -> IO Coder
getCoder conn RTT1Level k = coder1RTT <$> readArray (coders1RTT conn) k
getCoder conn lvl       _ = readArray (coders conn) lvl

getProtector :: Connection -> EncryptionLevel -> IO Protector
getProtector conn lvl = readArray (protectors conn) lvl

----------------------------------------------------------------

getCurrentKeyPhase :: Connection -> IO (Bool, PacketNumber)
getCurrentKeyPhase Connection{..} = readIORef currentKeyPhase

setCurrentKeyPhase :: Connection -> Bool -> PacketNumber -> IO ()
setCurrentKeyPhase Connection{..} k pn = writeIORef currentKeyPhase (k, pn)
