{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Types.Resumption where

import Codec.Serialise
import Data.Int (Int64)
import GHC.Generics
import Network.TLS hiding (Version)
import Network.TLS.QUIC

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
    deriving (Eq, Show, Generic)

instance Serialise ResumptionInfo

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
