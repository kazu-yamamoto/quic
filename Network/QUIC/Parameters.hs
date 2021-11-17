{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternSynonyms #-}

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

import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as Short
import System.IO.Unsafe (unsafeDupablePerformIO)

import Network.QUIC.Imports
import Network.QUIC.Types

encodeParameters :: Parameters -> ByteString
encodeParameters = encodeParameterList . toParameterList

decodeParameters :: ByteString -> Maybe Parameters
decodeParameters bs = fromParameterList <$> decodeParameterList bs

newtype Key = Key Word32 deriving (Eq, Show)
type Value = ByteString

type ParameterList = [(Key,Value)]

pattern OriginalDestinationConnectionId :: Key
pattern OriginalDestinationConnectionId  = Key 0x00
pattern MaxIdleTimeout                  :: Key
pattern MaxIdleTimeout                   = Key 0x01
pattern StateLessResetToken             :: Key
pattern StateLessResetToken              = Key 0x02
pattern MaxUdpPayloadSize               :: Key
pattern MaxUdpPayloadSize                = Key 0x03
pattern InitialMaxData                  :: Key
pattern InitialMaxData                   = Key 0x04
pattern InitialMaxStreamDataBidiLocal   :: Key
pattern InitialMaxStreamDataBidiLocal    = Key 0x05
pattern InitialMaxStreamDataBidiRemote  :: Key
pattern InitialMaxStreamDataBidiRemote   = Key 0x06
pattern InitialMaxStreamDataUni         :: Key
pattern InitialMaxStreamDataUni          = Key 0x07
pattern InitialMaxStreamsBidi           :: Key
pattern InitialMaxStreamsBidi            = Key 0x08
pattern InitialMaxStreamsUni            :: Key
pattern InitialMaxStreamsUni             = Key 0x09
pattern AckDelayExponent                :: Key
pattern AckDelayExponent                 = Key 0x0a
pattern MaxAckDelay                     :: Key
pattern MaxAckDelay                      = Key 0x0b
pattern DisableActiveMigration          :: Key
pattern DisableActiveMigration           = Key 0x0c
pattern PreferredAddress                :: Key
pattern PreferredAddress                 = Key 0x0d
pattern ActiveConnectionIdLimit         :: Key
pattern ActiveConnectionIdLimit          = Key 0x0e
pattern InitialSourceConnectionId       :: Key
pattern InitialSourceConnectionId        = Key 0x0f
pattern RetrySourceConnectionId         :: Key
pattern RetrySourceConnectionId          = Key 0x10
pattern Grease                          :: Key
pattern Grease                           = Key 0xff
pattern GreaseQuicBit                   :: Key
pattern GreaseQuicBit                    = Key 0x2ab2
pattern VersionInformation              :: Key
pattern VersionInformation               = Key 0xff73db


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
  , grease                          :: Maybe ByteString
  , greaseQuicBit                   :: Bool
  , versionInformation              :: Maybe VersionInfo
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
  , ackDelayExponent                   = 3
  , maxAckDelay                        = Milliseconds 25
  , disableActiveMigration             = False
  , preferredAddress                   = Nothing
  , activeConnectionIdLimit            = 2
  , initialSourceConnectionId          = Nothing
  , retrySourceConnectionId            = Nothing
  , grease                             = Nothing
  , greaseQuicBit                      = False
  , versionInformation                 = Nothing
  }

decInt :: ByteString -> Int
decInt = fromIntegral . decodeInt

encInt :: Int -> ByteString
encInt = encodeInt . fromIntegral

decMilliseconds :: ByteString -> Milliseconds
decMilliseconds = Milliseconds . fromIntegral . decodeInt

encMilliseconds :: Milliseconds -> ByteString
encMilliseconds (Milliseconds n) = encodeInt $ fromIntegral n

fromVersionInfo :: Maybe VersionInfo -> Value
fromVersionInfo Nothing                = "" -- never reach
fromVersionInfo (Just VersionInfo{..}) = unsafeDupablePerformIO $
    withWriteBuffer len $ \wbuf -> do
        let putVersion (Version ver) = write32 wbuf ver
        putVersion chosenVersion
        mapM_ putVersion otherVersions
  where
    len = 4 + length otherVersions

toVersionInfo :: Value -> Maybe VersionInfo
toVersionInfo bs
  | len < 3 || remainder /= 0   = Just brokenVersionInfo
  | otherwise                   = Just $ unsafeDupablePerformIO $
    withReadBuffer bs $ \rbuf -> do
        let getVersion = Version <$> read32 rbuf
        VersionInfo <$> getVersion <*> replicateM (cnt - 1) getVersion
  where
    len = BS.length bs
    (cnt,remainder) = len `divMod` 4

fromParameterList :: ParameterList -> Parameters
fromParameterList kvs = foldl' update params kvs
  where
    params = baseParameters
    update x (OriginalDestinationConnectionId,v)
        = x { originalDestinationConnectionId = Just (toCID v) }
    update x (MaxIdleTimeout,v)
        = x { maxIdleTimeout = decMilliseconds v }
    update x (StateLessResetToken,v)
        = x { statelessResetToken = Just (StatelessResetToken $ Short.toShort v) }
    update x (MaxUdpPayloadSize,v)
        = x { maxUdpPayloadSize = decInt v }
    update x (InitialMaxData,v)
        = x { initialMaxData = decInt v }
    update x (InitialMaxStreamDataBidiLocal,v)
        = x { initialMaxStreamDataBidiLocal = decInt v }
    update x (InitialMaxStreamDataBidiRemote,v)
        = x { initialMaxStreamDataBidiRemote = decInt v }
    update x (InitialMaxStreamDataUni,v)
        = x { initialMaxStreamDataUni = decInt v }
    update x (InitialMaxStreamsBidi,v)
        = x { initialMaxStreamsBidi = decInt v }
    update x (InitialMaxStreamsUni,v)
        = x { initialMaxStreamsUni = decInt v }
    update x (AckDelayExponent,v)
        = x { ackDelayExponent = decInt v }
    update x (MaxAckDelay,v)
        = x { maxAckDelay = decMilliseconds v }
    update x (DisableActiveMigration,_)
        = x { disableActiveMigration = True }
    update x (PreferredAddress,v)
        = x { preferredAddress = Just v }
    update x (ActiveConnectionIdLimit,v)
        = x { activeConnectionIdLimit = decInt v }
    update x (InitialSourceConnectionId,v)
        = x { initialSourceConnectionId = Just (toCID v) }
    update x (RetrySourceConnectionId,v)
        = x { retrySourceConnectionId = Just (toCID v) }
    update x (Grease,v)
        = x { grease = Just v }
    update x (GreaseQuicBit,_)
        = x { greaseQuicBit = True }
    update x (VersionInformation,v)
        = x { versionInformation = toVersionInfo v }
    update x _ = x

diff :: Eq a => Parameters -> (Parameters -> a) -> Key -> (a -> Value) -> Maybe (Key,Value)
diff params label key enc
  | val == val0 = Nothing
  | otherwise   = Just (key, enc val)
  where
    val = label params
    val0 = label baseParameters

toParameterList :: Parameters -> ParameterList
toParameterList p = catMaybes [
    diff p originalDestinationConnectionId
         OriginalDestinationConnectionId    (fromCID . fromJust)
  , diff p maxIdleTimeout          MaxIdleTimeout          encMilliseconds
  , diff p statelessResetToken     StateLessResetToken     encSRT
  , diff p maxUdpPayloadSize       MaxUdpPayloadSize       encInt
  , diff p initialMaxData          InitialMaxData          encInt
  , diff p initialMaxStreamDataBidiLocal  InitialMaxStreamDataBidiLocal  encInt
  , diff p initialMaxStreamDataBidiRemote InitialMaxStreamDataBidiRemote encInt
  , diff p initialMaxStreamDataUni InitialMaxStreamDataUni encInt
  , diff p initialMaxStreamsBidi   InitialMaxStreamsBidi   encInt
  , diff p initialMaxStreamsUni    InitialMaxStreamsUni    encInt
  , diff p ackDelayExponent        AckDelayExponent        encInt
  , diff p maxAckDelay             MaxAckDelay             encMilliseconds
  , diff p disableActiveMigration  DisableActiveMigration  (const "")
  , diff p preferredAddress        PreferredAddress        fromJust
  , diff p activeConnectionIdLimit ActiveConnectionIdLimit encInt
  , diff p initialSourceConnectionId
         InitialSourceConnectionId    (fromCID . fromJust)
  , diff p retrySourceConnectionId
         RetrySourceConnectionId      (fromCID . fromJust)
  , diff p greaseQuicBit           GreaseQuicBit           (const "")
  , diff p grease                  Grease                  fromJust
  , diff p versionInformation      VersionInformation      fromVersionInfo
  ]

encSRT :: Maybe StatelessResetToken -> ByteString
encSRT (Just (StatelessResetToken srt)) = Short.fromShort srt
encSRT _ = error "encSRT"

encodeParameterList :: ParameterList -> ByteString
encodeParameterList kvs = unsafeDupablePerformIO $
    withWriteBuffer 4096 $ \wbuf -> do -- for grease
        mapM_ (put wbuf) kvs
  where
    put wbuf (Key k,v) = do
        encodeInt' wbuf $ fromIntegral k
        encodeInt' wbuf $ fromIntegral $ BS.length v
        copyByteString wbuf v

decodeParameterList :: ByteString -> Maybe ParameterList
decodeParameterList bs = unsafeDupablePerformIO $ withReadBuffer bs (`go` id)
  where
    go rbuf build = do
       rest1 <- remainingSize rbuf
       if rest1 == 0 then
          return $ Just (build [])
       else do
          key <- fromIntegral <$> decodeInt' rbuf
          len <- fromIntegral <$> decodeInt' rbuf
          val <- extractByteString rbuf len
          go rbuf (build . ((Key key,val):))

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
