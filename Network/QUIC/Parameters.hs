{-# LANGUAGE OverloadedStrings #-}

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
    ParametersOriginalConnectionId
  | ParametersIdleTimeout
  | ParametersStateLessResetToken
  | ParametersMaxPacketSize
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
  | ParametersGrease
  deriving (Eq,Show)

fromParametersKeyId :: ParametersKeyId -> Word16
fromParametersKeyId ParametersOriginalConnectionId    =  0
fromParametersKeyId ParametersIdleTimeout             =  1
fromParametersKeyId ParametersStateLessResetToken     =  2
fromParametersKeyId ParametersMaxPacketSize           =  3
fromParametersKeyId ParametersMaxData                 =  4
fromParametersKeyId ParametersMaxStreamDataBidiLocal  =  5
fromParametersKeyId ParametersMaxStreamDataBidiRemote =  6
fromParametersKeyId ParametersMaxStreamDataUni        =  7
fromParametersKeyId ParametersMaxStreamsBidi          =  8
fromParametersKeyId ParametersMaxStreamsUni           =  9
fromParametersKeyId ParametersAckDelayExponent        = 10
fromParametersKeyId ParametersMaxAckDelay             = 11
fromParametersKeyId ParametersDisableMigration        = 12
fromParametersKeyId ParametersPreferredAddress        = 13
fromParametersKeyId ParametersActiveConnectionIdLimit = 14
fromParametersKeyId ParametersGrease                  = 255

toParametersKeyId :: Word16 -> Maybe ParametersKeyId
toParametersKeyId  0 = Just ParametersOriginalConnectionId
toParametersKeyId  1 = Just ParametersIdleTimeout
toParametersKeyId  2 = Just ParametersStateLessResetToken
toParametersKeyId  3 = Just ParametersMaxPacketSize
toParametersKeyId  4 = Just ParametersMaxData
toParametersKeyId  5 = Just ParametersMaxStreamDataBidiLocal
toParametersKeyId  6 = Just ParametersMaxStreamDataBidiRemote
toParametersKeyId  7 = Just ParametersMaxStreamDataUni
toParametersKeyId  8 = Just ParametersMaxStreamsBidi
toParametersKeyId  9 = Just ParametersMaxStreamsUni
toParametersKeyId 10 = Just ParametersAckDelayExponent
toParametersKeyId 11 = Just ParametersMaxAckDelay
toParametersKeyId 12 = Just ParametersDisableMigration
toParametersKeyId 13 = Just ParametersPreferredAddress
toParametersKeyId 14 = Just ParametersActiveConnectionIdLimit
toParametersKeyId 255 = Just ParametersGrease
toParametersKeyId _ = Nothing

-- | QUIC transport parameters.
data Parameters = Parameters {
    originalConnectionId    :: Maybe CID
  , idleTimeout             :: Int -- Milliseconds
  , statelessResetToken     :: Maybe StatelessResetToken -- 16 bytes
  , maxPacketSize           :: Int
  , maxData                 :: Int
  , maxStreamDataBidiLocal  :: Int
  , maxStreamDataBidiRemote :: Int
  , maxStreamDataUni        :: Int
  , maxStreamsBidi          :: Int
  , maxStreamsUni           :: Int
  , ackDelayExponent        :: Int
  , maxAckDelay             :: Int -- Millisenconds
  , disableMigration        :: Bool
  , preferredAddress        :: Maybe ByteString -- fixme
  , activeConnectionIdLimit :: Int
  , greaseParameter         :: Maybe ByteString
  } deriving (Eq,Show)

-- | The default value for QUIC transport parameters.
defaultParameters :: Parameters
defaultParameters = Parameters {
    originalConnectionId    = Nothing
  , idleTimeout             = 0 -- disabled
  , statelessResetToken     = Nothing
  , maxPacketSize           = 65527
  , maxData                 = -1
  , maxStreamDataBidiLocal  = -1
  , maxStreamDataBidiRemote = -1
  , maxStreamDataUni        = -1
  , maxStreamsBidi          = -1
  , maxStreamsUni           = -1
  , ackDelayExponent        = 8
  , maxAckDelay             = 25
  , disableMigration        = False
  , preferredAddress        = Nothing
  , activeConnectionIdLimit = 2
  , greaseParameter         = Nothing
  }

decInt :: ByteString -> Int
decInt = fromIntegral . decodeInt

encInt :: Int -> ByteString
encInt = encodeInt . fromIntegral

updateParameters :: Parameters -> ParametersList -> Parameters
updateParameters params kvs = foldl' update params kvs
  where
    update x (ParametersOriginalConnectionId,v)
        = x { originalConnectionId = Just (toCID v) }
    update x (ParametersIdleTimeout,v)
        = x { idleTimeout = decInt v }
    update x (ParametersStateLessResetToken,v)
        = x {statelessResetToken = Just (StatelessResetToken $ Short.toShort v) }
    update x (ParametersMaxPacketSize,v)
        = x {maxPacketSize = decInt v}
    update x (ParametersMaxData,v)
        = x {maxData = decInt v}
    update x (ParametersMaxStreamDataBidiLocal,v)
        = x {maxStreamDataBidiLocal = decInt v}
    update x (ParametersMaxStreamDataBidiRemote,v)
        = x {maxStreamDataBidiRemote = decInt v}
    update x (ParametersMaxStreamDataUni,v)
        = x {maxStreamDataUni = decInt v}
    update x (ParametersMaxStreamsBidi,v)
        = x {maxStreamsBidi = decInt v}
    update x (ParametersMaxStreamsUni,v)
        = x {maxStreamsUni = decInt v}
    update x (ParametersAckDelayExponent,v)
        = x {ackDelayExponent = decInt v}
    update x (ParametersMaxAckDelay,v)
        = x {maxAckDelay = decInt v}
    update x (ParametersDisableMigration,_)
        = x {disableMigration = True}
    update x (ParametersPreferredAddress,v)
        = x {preferredAddress = Just v}
    update x (ParametersActiveConnectionIdLimit,v)
        = x {activeConnectionIdLimit = decInt v}
    update x (ParametersGrease,v)
        = x {greaseParameter = Just v}

diff :: Eq a => Parameters -> (Parameters -> a) -> ParametersKeyId -> (a -> ParametersValue) -> Maybe (ParametersKeyId,ParametersValue)
diff params label key enc
  | val == val0 = Nothing
  | otherwise   = Just (key, enc val)
  where
    val = label params
    val0 = label defaultParameters

diffParameters :: Parameters -> ParametersList
diffParameters p = catMaybes [
    diff p originalConnectionId    ParametersOriginalConnectionId    (fromCID . fromJust)
  , diff p idleTimeout             ParametersIdleTimeout             encInt
  , diff p statelessResetToken     ParametersStateLessResetToken     encSRT
  , diff p maxPacketSize           ParametersMaxPacketSize           encInt
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
  , maxStreamsBidi          =       1
  , maxStreamsUni           =     100
  , idleTimeout             =   30000
  , maxPacketSize           =    1280
  , activeConnectionIdLimit =       3
  }
