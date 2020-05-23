{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Parameters where

import qualified Control.Exception as E
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as Short
import System.IO.Unsafe (unsafeDupablePerformIO)

import Network.QUIC.Imports
import Network.QUIC.Types

type ParametersList = [(ParametersKeyId,ParametersValue)]

type ParametersValue = ByteString

data ParametersKeyId =
    ParametersOriginalDestinationConnectionId
  | ParametersIdleTimeout
  | ParametersStateLessResetToken
  | ParametersMaxUdpPayloadSize
  | ParametersMaxData
  | ParametersMaxStreamDataBidiLocal
  | ParametersMaxStreamDataBidiRemote
  | ParametersMaxStreamDataUni
  | ParametersMaxStreamsBidi
  | ParametersMaxStreamsUni
  | ParametersAckDelayExponent
  | ParametersMaxAckDelay
  | ParametersDisableMigration
  | ParametersPreferredAddress
  | ParametersActiveConnectionIdLimit
  | ParametersInitialSourceConnectionId
  | ParametersRetrySourceConnectionId
  | ParametersGrease
  deriving (Eq,Show)

fromParametersKeyId :: ParametersKeyId -> Word16
fromParametersKeyId ParametersOriginalDestinationConnectionId = 0x00
fromParametersKeyId ParametersIdleTimeout                     = 0x01
fromParametersKeyId ParametersStateLessResetToken             = 0x02
fromParametersKeyId ParametersMaxUdpPayloadSize               = 0x03
fromParametersKeyId ParametersMaxData                         = 0x04
fromParametersKeyId ParametersMaxStreamDataBidiLocal          = 0x05
fromParametersKeyId ParametersMaxStreamDataBidiRemote         = 0x06
fromParametersKeyId ParametersMaxStreamDataUni                = 0x07
fromParametersKeyId ParametersMaxStreamsBidi                  = 0x08
fromParametersKeyId ParametersMaxStreamsUni                   = 0x09
fromParametersKeyId ParametersAckDelayExponent                = 0x0a
fromParametersKeyId ParametersMaxAckDelay                     = 0x0b
fromParametersKeyId ParametersDisableMigration                = 0x0c
fromParametersKeyId ParametersPreferredAddress                = 0x0d
fromParametersKeyId ParametersActiveConnectionIdLimit         = 0x0e
fromParametersKeyId ParametersInitialSourceConnectionId       = 0x0f
fromParametersKeyId ParametersRetrySourceConnectionId         = 0x10
fromParametersKeyId ParametersGrease                          = 0xff

toParametersKeyId :: Word16 -> Maybe ParametersKeyId
toParametersKeyId 0x00 = Just ParametersOriginalDestinationConnectionId
toParametersKeyId 0x01 = Just ParametersIdleTimeout
toParametersKeyId 0x02 = Just ParametersStateLessResetToken
toParametersKeyId 0x03 = Just ParametersMaxUdpPayloadSize
toParametersKeyId 0x04 = Just ParametersMaxData
toParametersKeyId 0x05 = Just ParametersMaxStreamDataBidiLocal
toParametersKeyId 0x06 = Just ParametersMaxStreamDataBidiRemote
toParametersKeyId 0x07 = Just ParametersMaxStreamDataUni
toParametersKeyId 0x08 = Just ParametersMaxStreamsBidi
toParametersKeyId 0x09 = Just ParametersMaxStreamsUni
toParametersKeyId 0x0a = Just ParametersAckDelayExponent
toParametersKeyId 0x0b = Just ParametersMaxAckDelay
toParametersKeyId 0x0c = Just ParametersDisableMigration
toParametersKeyId 0x0d = Just ParametersPreferredAddress
toParametersKeyId 0x0e = Just ParametersActiveConnectionIdLimit
toParametersKeyId 0x0f = Just ParametersInitialSourceConnectionId
toParametersKeyId 0x10 = Just ParametersRetrySourceConnectionId
toParametersKeyId 0xff = Just ParametersGrease
toParametersKeyId _    = Nothing

-- | QUIC transport parameters.
data Parameters = Parameters {
    originalDestinationConnectionId :: Maybe CID
  , idleTimeout                     :: Int -- Milliseconds
  , statelessResetToken             :: Maybe StatelessResetToken -- 16 bytes
  , maxUdpPayloadSize               :: Int
  , maxData                         :: Int
  , maxStreamDataBidiLocal          :: Int
  , maxStreamDataBidiRemote         :: Int
  , maxStreamDataUni                :: Int
  , maxStreamsBidi                  :: Int
  , maxStreamsUni                   :: Int
  , ackDelayExponent                :: Int
  , maxAckDelay                     :: Int -- Millisenconds
  , disableMigration                :: Bool
  , preferredAddress                :: Maybe ByteString -- fixme
  , activeConnectionIdLimit         :: Int
  , greaseParameter                 :: Maybe ByteString
  , initialSourceConnectionId       :: Maybe CID
  , retrySourceConnectionId         :: Maybe CID
  } deriving (Eq,Show)

-- | The default value for QUIC transport parameters.
defaultParameters :: Parameters
defaultParameters = Parameters {
    originalDestinationConnectionId    = Nothing
  , idleTimeout                        = 0 -- disabled
  , statelessResetToken                = Nothing
  , maxUdpPayloadSize                  = 65527
  , maxData                            = -1
  , maxStreamDataBidiLocal             = -1
  , maxStreamDataBidiRemote            = -1
  , maxStreamDataUni                   = -1
  , maxStreamsBidi                     = -1
  , maxStreamsUni                      = -1
  , ackDelayExponent                   = 8
  , maxAckDelay                        = 25
  , disableMigration                   = False
  , preferredAddress                   = Nothing
  , activeConnectionIdLimit            = 2
  , greaseParameter                    = Nothing
  , initialSourceConnectionId          = Nothing
  , retrySourceConnectionId            = Nothing
  }

decInt :: ByteString -> Int
decInt = fromIntegral . decodeInt

encInt :: Int -> ByteString
encInt = encodeInt . fromIntegral

updateParameters :: Parameters -> ParametersList -> Parameters
updateParameters params kvs = foldl' update params kvs
  where
    update x (ParametersOriginalDestinationConnectionId,v)
        = x { originalDestinationConnectionId = Just (toCID v) }
    update x (ParametersIdleTimeout,v)
        = x { idleTimeout = decInt v }
    update x (ParametersStateLessResetToken,v)
        = x { statelessResetToken = Just (StatelessResetToken $ Short.toShort v) }
    update x (ParametersMaxUdpPayloadSize,v)
        = x { maxUdpPayloadSize = decInt v }
    update x (ParametersMaxData,v)
        = x { maxData = decInt v }
    update x (ParametersMaxStreamDataBidiLocal,v)
        = x { maxStreamDataBidiLocal = decInt v }
    update x (ParametersMaxStreamDataBidiRemote,v)
        = x { maxStreamDataBidiRemote = decInt v }
    update x (ParametersMaxStreamDataUni,v)
        = x { maxStreamDataUni = decInt v }
    update x (ParametersMaxStreamsBidi,v)
        = x { maxStreamsBidi = decInt v }
    update x (ParametersMaxStreamsUni,v)
        = x { maxStreamsUni = decInt v }
    update x (ParametersAckDelayExponent,v)
        = x { ackDelayExponent = decInt v }
    update x (ParametersMaxAckDelay,v)
        = x { maxAckDelay = decInt v }
    update x (ParametersDisableMigration,_)
        = x { disableMigration = True }
    update x (ParametersPreferredAddress,v)
        = x { preferredAddress = Just v }
    update x (ParametersActiveConnectionIdLimit,v)
        = x { activeConnectionIdLimit = decInt v }
    update x (ParametersGrease,v)
        = x { greaseParameter = Just v }
    update x (ParametersInitialSourceConnectionId,v)
        = x { initialSourceConnectionId = Just (toCID v) }
    update x (ParametersRetrySourceConnectionId,v)
        = x { retrySourceConnectionId = Just (toCID v) }

diff :: Eq a => Parameters -> (Parameters -> a) -> ParametersKeyId -> (a -> ParametersValue) -> Maybe (ParametersKeyId,ParametersValue)
diff params label key enc
  | val == val0 = Nothing
  | otherwise   = Just (key, enc val)
  where
    val = label params
    val0 = label defaultParameters

diffParameters :: Parameters -> ParametersList
diffParameters p = catMaybes [
    diff p originalDestinationConnectionId
         ParametersOriginalDestinationConnectionId    (fromCID . fromJust)
  , diff p idleTimeout             ParametersIdleTimeout             encInt
  , diff p statelessResetToken     ParametersStateLessResetToken     encSRT
  , diff p maxUdpPayloadSize       ParametersMaxUdpPayloadSize       encInt
  , diff p maxData                 ParametersMaxData                 encInt
  , diff p maxStreamDataBidiLocal  ParametersMaxStreamDataBidiLocal  encInt
  , diff p maxStreamDataBidiRemote ParametersMaxStreamDataBidiRemote encInt
  , diff p maxStreamDataUni        ParametersMaxStreamDataUni        encInt
  , diff p maxStreamsBidi          ParametersMaxStreamsBidi          encInt
  , diff p maxStreamsUni           ParametersMaxStreamsUni           encInt
  , diff p ackDelayExponent        ParametersAckDelayExponent        encInt
  , diff p maxAckDelay             ParametersMaxAckDelay             encInt
  , diff p disableMigration        ParametersDisableMigration        (const "")
  , diff p preferredAddress        ParametersPreferredAddress        fromJust
  , diff p activeConnectionIdLimit ParametersActiveConnectionIdLimit encInt
  , diff p initialSourceConnectionId
         ParametersInitialSourceConnectionId    (fromCID . fromJust)
  , diff p retrySourceConnectionId
         ParametersRetrySourceConnectionId      (fromCID . fromJust)
  , diff p greaseParameter         ParametersGrease                  fromJust
  ]

encSRT :: Maybe StatelessResetToken -> ByteString
encSRT (Just (StatelessResetToken srt)) = Short.fromShort srt
encSRT _ = error "encSRT"

encodeParametersList :: ParametersList -> ByteString
encodeParametersList kvs = unsafeDupablePerformIO $
    withWriteBuffer 2048 $ \wbuf -> do -- for grease
        mapM_ (put wbuf) kvs
  where
    put wbuf (k,v) = do
        encodeInt' wbuf $ fromIntegral $ fromParametersKeyId k
        encodeInt' wbuf $ fromIntegral $ BS.length v
        copyByteString wbuf v

decodeParametersList :: ByteString -> Maybe ParametersList
decodeParametersList bs = unsafeDupablePerformIO
    (withReadBuffer bs (`go` id) `E.catch` \BufferOverrun -> return Nothing)
  where
    go rbuf build = do
       rest1 <- remainingSize rbuf
       if rest1 == 0 then
          return $ Just (build [])
       else do
          key <- fromIntegral <$> decodeInt' rbuf
          len <- fromIntegral <$> decodeInt' rbuf
          case toParametersKeyId key of
             Nothing -> do
               ff rbuf len
               go rbuf build
             Just keyid -> do
               val <- extractByteString rbuf len
               go rbuf (build . ((keyid,val):))

-- | An example parameters obsoleted in the near future.
exampleParameters :: Parameters
exampleParameters = defaultParameters {
    maxStreamDataBidiLocal  =  262144
  , maxStreamDataBidiRemote =  262144
  , maxStreamDataUni        =  262144
  , maxData                 = 1048576
  , maxStreamsBidi          =     100
  , maxStreamsUni           =       3
  , idleTimeout             =   30000
  , maxUdpPayloadSize       =    1280
  , activeConnectionIdLimit =       3
  }

data AuthCIDs = AuthCIDs {
    initSrcCID  :: Maybe CID
  , origDstCID  :: Maybe CID
  , retrySrcCID :: Maybe CID
  }

setCIDsToParameters :: AuthCIDs -> Parameters -> Parameters
setCIDsToParameters AuthCIDs{..} params = params {
    originalDestinationConnectionId = origDstCID
  , initialSourceConnectionId       = initSrcCID
  , retrySourceConnectionId         = retrySrcCID
  }

getCIDsToParameters :: Parameters -> AuthCIDs
getCIDsToParameters Parameters{..} = AuthCIDs {
    origDstCID  = originalDestinationConnectionId
  , initSrcCID  = initialSourceConnectionId
  , retrySrcCID = retrySourceConnectionId
  }

defaultAuthCIDs :: AuthCIDs
defaultAuthCIDs = AuthCIDs Nothing Nothing Nothing
