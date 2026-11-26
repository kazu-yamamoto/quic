{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Types.Resumption where

import Network.TLS hiding (Version)
import Network.TLS.QUIC

import Network.QUIC.Codec
import Network.QUIC.Imports hiding (word8)
import Network.QUIC.Types.Frame
import Network.QUIC.Types.Packet

type SessionEstablish = SessionID -> SessionData -> IO (Maybe Ticket)

-- | Information about resumption
data ResumptionInfo = ResumptionInfo
    { resumptionVersion :: Version
    , resumptionSession :: [(SessionID, SessionData)]
    , resumptionToken :: Token
    , resumptionRetry :: Bool
    , resumptionActiveConnectionIdLimit :: Int64
    , resumptionInitialMaxData :: Int64
    , resumptionInitialMaxStreamDataBidiLocal :: Int64
    , resumptionInitialMaxStreamDataBidiRemote :: Int64
    , resumptionInitialMaxStreamDataUni :: Int64
    , resumptionInitialMaxStreamsBidi :: Int64
    , resumptionInitialMaxStreamsUni :: Int64
    , resumptionMaxDatagramFrameSize :: Int64
    }
    deriving (Eq, Show)

-- | Encoding 'ResumptionInfo', e.g. to store it.  The format starts with
--   its own version, and each 'SessionData' is in tls's own format
--   ('encodeSessionData').
--
-- @since 0.4.0
encodeResumptionInfo :: ResumptionInfo -> ByteString
encodeResumptionInfo ResumptionInfo{..} =
    runBuilder $
        word8 resumptionFormat
            <> word32BE ver
            <> word32BE (fromIntegral $ length resumptionSession)
            <> foldMap session resumptionSession
            <> opaque32 resumptionToken
            <> word8 (if resumptionRetry then 1 else 0)
            <> foldMap
                int64BE
                [ resumptionActiveConnectionIdLimit
                , resumptionInitialMaxData
                , resumptionInitialMaxStreamDataBidiLocal
                , resumptionInitialMaxStreamDataBidiRemote
                , resumptionInitialMaxStreamDataUni
                , resumptionInitialMaxStreamsBidi
                , resumptionInitialMaxStreamsUni
                , resumptionMaxDatagramFrameSize
                ]
  where
    Version ver = resumptionVersion
    session (sid, sd) = opaque32 sid <> opaque32 (encodeSessionData sd)

-- | Decoding what 'encodeResumptionInfo' made.  'Nothing' for anything
--   else, including the format of another release which this one cannot
--   read.
--
-- @since 0.4.0
decodeResumptionInfo :: ByteString -> Maybe ResumptionInfo
decodeResumptionInfo = runParser $ do
    fmt <- getWord8
    when (fmt /= resumptionFormat) $ fail "unknown format"
    ver <- Version <$> getWord32
    n <- getWord32
    sessions <- replicateM (fromIntegral n) session
    token <- getOpaque32
    retry <-
        getWord8 >>= \b -> case b of
            0 -> return False
            1 -> return True
            _ -> fail "bad retry"
    [a, b, c, d, e, f, g, h] <- replicateM 8 getInt64
    return
        ResumptionInfo
            { resumptionVersion = ver
            , resumptionSession = sessions
            , resumptionToken = token
            , resumptionRetry = retry
            , resumptionActiveConnectionIdLimit = a
            , resumptionInitialMaxData = b
            , resumptionInitialMaxStreamDataBidiLocal = c
            , resumptionInitialMaxStreamDataBidiRemote = d
            , resumptionInitialMaxStreamDataUni = e
            , resumptionInitialMaxStreamsBidi = f
            , resumptionInitialMaxStreamsUni = g
            , resumptionMaxDatagramFrameSize = h
            }
  where
    session = do
        sid <- getOpaque32
        Just sd <- decodeSessionData <$> getOpaque32
        return (sid, sd)

resumptionFormat :: Word8
resumptionFormat = 1

defaultResumptionInfo :: ResumptionInfo
defaultResumptionInfo =
    ResumptionInfo
        { resumptionVersion = Version1
        , resumptionSession = []
        , resumptionToken = emptyToken
        , resumptionRetry = False
        , resumptionActiveConnectionIdLimit = 2 -- see baseParameters
        , resumptionInitialMaxData = 0
        , resumptionInitialMaxStreamDataBidiLocal = 0
        , resumptionInitialMaxStreamDataBidiRemote = 0
        , resumptionInitialMaxStreamDataUni = 0
        , resumptionInitialMaxStreamsBidi = 0
        , resumptionInitialMaxStreamsUni = 0
        , resumptionMaxDatagramFrameSize = 0
        }

-- | Is 0RTT possible?
is0RTTPossible :: ResumptionInfo -> Bool
is0RTTPossible ResumptionInfo{..} =
    rtt0OK && (not resumptionRetry || resumptionToken /= emptyToken)
  where
    rtt0OK =
        any
            (\(_, sd) -> sessionMaxEarlyDataSize sd == quicMaxEarlyDataSize)
            resumptionSession

-- | Is resumption possible?
isResumptionPossible :: ResumptionInfo -> Bool
isResumptionPossible ResumptionInfo{..} = not $ null resumptionSession
