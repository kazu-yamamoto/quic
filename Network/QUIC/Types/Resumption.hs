{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Types.Resumption where

import Codec.Serialise
import GHC.Generics
import Network.TLS hiding (Version)
import Network.TLS.QUIC

import Network.QUIC.Imports
import Network.QUIC.Types.Frame
import Network.QUIC.Types.Packet

type SessionEstablish = SessionID -> SessionData -> IO (Maybe Ticket)

-- | Information about resumption
data ResumptionInfo = ResumptionInfo
    { resumptionVersion :: Version
    , resumptionSession :: Maybe (SessionID, SessionData)
    , resumptionToken :: Token
    , resumptionRetry :: Bool
    }
    deriving (Eq, Show, Generic)

instance Serialise ResumptionInfo

defaultResumptionInfo :: ResumptionInfo
defaultResumptionInfo =
    ResumptionInfo
        { resumptionVersion = Version1
        , resumptionSession = Nothing
        , resumptionToken = emptyToken
        , resumptionRetry = False
        }

-- | Is 0RTT possible?
is0RTTPossible :: ResumptionInfo -> Bool
is0RTTPossible ResumptionInfo{..} =
    rtt0OK && (not resumptionRetry || resumptionToken /= emptyToken)
  where
    rtt0OK = case resumptionSession of
        Nothing -> False
        Just (_, sd) -> sessionMaxEarlyDataSize sd == quicMaxEarlyDataSize

-- | Is resumption possible?
isResumptionPossible :: ResumptionInfo -> Bool
isResumptionPossible ResumptionInfo{..} = isJust resumptionSession
