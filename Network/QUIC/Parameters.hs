{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Parameters (
    Parameters(..)
  , defaultParameters
  , baseParameters -- only for Connection
  , encodeParameters
  , decodeParameters
  , AuthCIDs(..)
  , defaultAuthCIDs
  , setCIDsToParameters
  , getCIDsToParameters
  ) where

import qualified Control.Exception as E
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as Short
import System.IO.Unsafe (unsafeDupablePerformIO)

import Network.QUIC.Imports
import Network.QUIC.Types

encodeParameters :: Parameters -> ByteString
encodeParameters = encodeParameterList . toParameterList

decodeParameters :: ByteString -> Maybe Parameters
decodeParameters bs = fromParameterList <$> decodeParameterList bs

type ParameterList = [(ParameterKeyId,ParameterValue)]

type ParameterValue = ByteString

data ParameterKeyId =
    ParameterOriginalDestinationConnectionId
  | ParameterMaxIdleTimeout
  | ParameterStateLessResetToken
  | ParameterMaxUdpPayloadSize
  | ParameterInitialMaxData
  | ParameterInitialMaxStreamDataBidiLocal
  | ParameterInitialMaxStreamDataBidiRemote
  | ParameterInitialMaxStreamDataUni
  | ParameterInitialMaxStreamsBidi
  | ParameterInitialMaxStreamsUni
  | ParameterAckDelayExponent
  | ParameterMaxAckDelay
  | ParameterDisableActiveMigration
  | ParameterPreferredAddress
  | ParameterActiveConnectionIdLimit
  | ParameterInitialSourceConnectionId
  | ParameterRetrySourceConnectionId
  | ParameterGrease
  | ParameterGreaseQuicBit
  deriving (Eq,Show)

fromParameterKeyId :: ParameterKeyId -> Word16
fromParameterKeyId ParameterOriginalDestinationConnectionId = 0x00
fromParameterKeyId ParameterMaxIdleTimeout                  = 0x01
fromParameterKeyId ParameterStateLessResetToken             = 0x02
fromParameterKeyId ParameterMaxUdpPayloadSize               = 0x03
fromParameterKeyId ParameterInitialMaxData                  = 0x04
fromParameterKeyId ParameterInitialMaxStreamDataBidiLocal   = 0x05
fromParameterKeyId ParameterInitialMaxStreamDataBidiRemote  = 0x06
fromParameterKeyId ParameterInitialMaxStreamDataUni         = 0x07
fromParameterKeyId ParameterInitialMaxStreamsBidi           = 0x08
fromParameterKeyId ParameterInitialMaxStreamsUni            = 0x09
fromParameterKeyId ParameterAckDelayExponent                = 0x0a
fromParameterKeyId ParameterMaxAckDelay                     = 0x0b
fromParameterKeyId ParameterDisableActiveMigration          = 0x0c
fromParameterKeyId ParameterPreferredAddress                = 0x0d
fromParameterKeyId ParameterActiveConnectionIdLimit         = 0x0e
fromParameterKeyId ParameterInitialSourceConnectionId       = 0x0f
fromParameterKeyId ParameterRetrySourceConnectionId         = 0x10
fromParameterKeyId ParameterGrease                          = 0xff
fromParameterKeyId ParameterGreaseQuicBit                   = 0x2ab2

toParameterKeyId :: Word16 -> Maybe ParameterKeyId
toParameterKeyId 0x00 = Just ParameterOriginalDestinationConnectionId
toParameterKeyId 0x01 = Just ParameterMaxIdleTimeout
toParameterKeyId 0x02 = Just ParameterStateLessResetToken
toParameterKeyId 0x03 = Just ParameterMaxUdpPayloadSize
toParameterKeyId 0x04 = Just ParameterInitialMaxData
toParameterKeyId 0x05 = Just ParameterInitialMaxStreamDataBidiLocal
toParameterKeyId 0x06 = Just ParameterInitialMaxStreamDataBidiRemote
toParameterKeyId 0x07 = Just ParameterInitialMaxStreamDataUni
toParameterKeyId 0x08 = Just ParameterInitialMaxStreamsBidi
toParameterKeyId 0x09 = Just ParameterInitialMaxStreamsUni
toParameterKeyId 0x0a = Just ParameterAckDelayExponent
toParameterKeyId 0x0b = Just ParameterMaxAckDelay
toParameterKeyId 0x0c = Just ParameterDisableActiveMigration
toParameterKeyId 0x0d = Just ParameterPreferredAddress
toParameterKeyId 0x0e = Just ParameterActiveConnectionIdLimit
toParameterKeyId 0x0f = Just ParameterInitialSourceConnectionId
toParameterKeyId 0x10 = Just ParameterRetrySourceConnectionId
toParameterKeyId 0xff = Just ParameterGrease
toParameterKeyId 0x2ab2 = Just ParameterGreaseQuicBit
toParameterKeyId _    = Nothing

-- | QUIC transport parameters.
data Parameters = Parameters {
    originalDestinationConnectionId :: Maybe CID
  , maxIdleTimeout                  :: Milliseconds
  , statelessResetToken             :: Maybe StatelessResetToken -- 16 bytes
  , maxUdpPayloadSize               :: Int
  , initialMaxData                  :: Int
  , initialMaxStreamDataBidiLocal   :: Int
  , initialMaxStreamDataBidiRemote  :: Int
  , initialMaxStreamDataUni         :: Int
  , initialMaxStreamsBidi           :: Int
  , initialMaxStreamsUni            :: Int
  , ackDelayExponent                :: Int
  , maxAckDelay                     :: Milliseconds
  , disableActiveMigration          :: Bool
  , preferredAddress                :: Maybe ByteString -- fixme
  , activeConnectionIdLimit         :: Int
  , initialSourceConnectionId       :: Maybe CID
  , retrySourceConnectionId         :: Maybe CID
  , greaseParameter                 :: Maybe ByteString
  , greaseQuicBit                   :: Bool
  } deriving (Eq,Show)

-- | The default value for QUIC transport parameters.
baseParameters :: Parameters
baseParameters = Parameters {
    originalDestinationConnectionId    = Nothing
  , maxIdleTimeout                     = Milliseconds 0 -- disabled
  , statelessResetToken                = Nothing
  , maxUdpPayloadSize                  = 65527
  , initialMaxData                     = 0
  , initialMaxStreamDataBidiLocal      = 0
  , initialMaxStreamDataBidiRemote     = 0
  , initialMaxStreamDataUni            = 0
  , initialMaxStreamsBidi              = 0
  , initialMaxStreamsUni               = 0
  , ackDelayExponent                   = 8
  , maxAckDelay                        = Milliseconds 25
  , disableActiveMigration             = False
  , preferredAddress                   = Nothing
  , activeConnectionIdLimit            = 2
  , initialSourceConnectionId          = Nothing
  , retrySourceConnectionId            = Nothing
  , greaseParameter                    = Nothing
  , greaseQuicBit                      = False
  }

decInt :: ByteString -> Int
decInt = fromIntegral . decodeInt

encInt :: Int -> ByteString
encInt = encodeInt . fromIntegral

decMilliseconds :: ByteString -> Milliseconds
decMilliseconds = Milliseconds . fromIntegral . decodeInt

encMilliseconds :: Milliseconds -> ByteString
encMilliseconds (Milliseconds n) = encodeInt $ fromIntegral n

fromParameterList :: ParameterList -> Parameters
fromParameterList kvs = foldl' update params kvs
  where
    params = baseParameters
    update x (ParameterOriginalDestinationConnectionId,v)
        = x { originalDestinationConnectionId = Just (toCID v) }
    update x (ParameterMaxIdleTimeout,v)
        = x { maxIdleTimeout = decMilliseconds v }
    update x (ParameterStateLessResetToken,v)
        = x { statelessResetToken = Just (StatelessResetToken $ Short.toShort v) }
    update x (ParameterMaxUdpPayloadSize,v)
        = x { maxUdpPayloadSize = decInt v }
    update x (ParameterInitialMaxData,v)
        = x { initialMaxData = decInt v }
    update x (ParameterInitialMaxStreamDataBidiLocal,v)
        = x { initialMaxStreamDataBidiLocal = decInt v }
    update x (ParameterInitialMaxStreamDataBidiRemote,v)
        = x { initialMaxStreamDataBidiRemote = decInt v }
    update x (ParameterInitialMaxStreamDataUni,v)
        = x { initialMaxStreamDataUni = decInt v }
    update x (ParameterInitialMaxStreamsBidi,v)
        = x { initialMaxStreamsBidi = decInt v }
    update x (ParameterInitialMaxStreamsUni,v)
        = x { initialMaxStreamsUni = decInt v }
    update x (ParameterAckDelayExponent,v)
        = x { ackDelayExponent = decInt v }
    update x (ParameterMaxAckDelay,v)
        = x { maxAckDelay = decMilliseconds v }
    update x (ParameterDisableActiveMigration,_)
        = x { disableActiveMigration = True }
    update x (ParameterPreferredAddress,v)
        = x { preferredAddress = Just v }
    update x (ParameterActiveConnectionIdLimit,v)
        = x { activeConnectionIdLimit = decInt v }
    update x (ParameterInitialSourceConnectionId,v)
        = x { initialSourceConnectionId = Just (toCID v) }
    update x (ParameterRetrySourceConnectionId,v)
        = x { retrySourceConnectionId = Just (toCID v) }
    update x (ParameterGrease,v)
        = x { greaseParameter = Just v }
    update x (ParameterGreaseQuicBit,_)
        = x { greaseQuicBit = True }

diff :: Eq a => Parameters -> (Parameters -> a) -> ParameterKeyId -> (a -> ParameterValue) -> Maybe (ParameterKeyId,ParameterValue)
diff params label key enc
  | val == val0 = Nothing
  | otherwise   = Just (key, enc val)
  where
    val = label params
    val0 = label baseParameters

toParameterList :: Parameters -> ParameterList
toParameterList p = catMaybes [
    diff p originalDestinationConnectionId
         ParameterOriginalDestinationConnectionId    (fromCID . fromJust)
  , diff p maxIdleTimeout          ParameterMaxIdleTimeout          encMilliseconds
  , diff p statelessResetToken     ParameterStateLessResetToken     encSRT
  , diff p maxUdpPayloadSize       ParameterMaxUdpPayloadSize       encInt
  , diff p initialMaxData          ParameterInitialMaxData          encInt
  , diff p initialMaxStreamDataBidiLocal  ParameterInitialMaxStreamDataBidiLocal  encInt
  , diff p initialMaxStreamDataBidiRemote ParameterInitialMaxStreamDataBidiRemote encInt
  , diff p initialMaxStreamDataUni ParameterInitialMaxStreamDataUni encInt
  , diff p initialMaxStreamsBidi   ParameterInitialMaxStreamsBidi   encInt
  , diff p initialMaxStreamsUni    ParameterInitialMaxStreamsUni    encInt
  , diff p ackDelayExponent        ParameterAckDelayExponent        encInt
  , diff p maxAckDelay             ParameterMaxAckDelay             encMilliseconds
  , diff p disableActiveMigration  ParameterDisableActiveMigration  (const "")
  , diff p preferredAddress        ParameterPreferredAddress        fromJust
  , diff p activeConnectionIdLimit ParameterActiveConnectionIdLimit encInt
  , diff p initialSourceConnectionId
         ParameterInitialSourceConnectionId    (fromCID . fromJust)
  , diff p retrySourceConnectionId
         ParameterRetrySourceConnectionId      (fromCID . fromJust)
  , diff p greaseQuicBit           ParameterGreaseQuicBit           (const "")
  , diff p greaseParameter         ParameterGrease                  fromJust
  ]

encSRT :: Maybe StatelessResetToken -> ByteString
encSRT (Just (StatelessResetToken srt)) = Short.fromShort srt
encSRT _ = error "encSRT"

encodeParameterList :: ParameterList -> ByteString
encodeParameterList kvs = unsafeDupablePerformIO $
    withWriteBuffer 2048 $ \wbuf -> do -- for grease
        mapM_ (put wbuf) kvs
  where
    put wbuf (k,v) = do
        encodeInt' wbuf $ fromIntegral $ fromParameterKeyId k
        encodeInt' wbuf $ fromIntegral $ BS.length v
        copyByteString wbuf v

decodeParameterList :: ByteString -> Maybe ParameterList
decodeParameterList bs = unsafeDupablePerformIO
    (withReadBuffer bs (`go` id) `E.catch` \BufferOverrun -> return Nothing)
  where
    go rbuf build = do
       rest1 <- remainingSize rbuf
       if rest1 == 0 then
          return $ Just (build [])
       else do
          key <- fromIntegral <$> decodeInt' rbuf
          len <- fromIntegral <$> decodeInt' rbuf
          case toParameterKeyId key of
             Nothing -> do
               ff rbuf len
               go rbuf build
             Just keyid -> do
               val <- extractByteString rbuf len
               go rbuf (build . ((keyid,val):))

-- | An example parameters obsoleted in the near future.
defaultParameters :: Parameters
defaultParameters = baseParameters {
    maxIdleTimeout                 = microToMilli idleTimeout -- 30000
  , maxUdpPayloadSize              = maximumUdpPayloadSize -- 2048
  , initialMaxData                 = 1048576
  , initialMaxStreamDataBidiLocal  =  262144
  , initialMaxStreamDataBidiRemote =  262144
  , initialMaxStreamDataUni        =  262144
  , initialMaxStreamsBidi          =     100
  , initialMaxStreamsUni           =       3
  , activeConnectionIdLimit        =       3
  , greaseQuicBit                  = True
  }

data AuthCIDs = AuthCIDs {
    initSrcCID  :: Maybe CID
  , origDstCID  :: Maybe CID
  , retrySrcCID :: Maybe CID
  } deriving (Eq, Show)

defaultAuthCIDs :: AuthCIDs
defaultAuthCIDs = AuthCIDs Nothing Nothing Nothing

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
