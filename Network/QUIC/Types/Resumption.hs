{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Types.Resumption where

import Network.TLS
import Network.TLS.QUIC

import Network.QUIC.Imports
import Network.QUIC.Types.Frame

type SessionEstablish = SessionID -> SessionData -> IO ()

-- | Information about resumption
data ResumptionInfo = ResumptionInfo {
    resumptionSession :: Maybe (SessionID, SessionData)
  , resumptionToken   :: Token
  , resumptionRetry   :: Bool
  } deriving (Eq, Show)

defaultResumptionInfo :: ResumptionInfo
defaultResumptionInfo = ResumptionInfo {
    resumptionSession = Nothing
  , resumptionToken   = emptyToken
  , resumptionRetry   = False
  }

-- | Is 0RTT possible?
is0RTTPossible :: ResumptionInfo -> Bool
is0RTTPossible ResumptionInfo{..} =
    rtt0OK && (not resumptionRetry || resumptionToken /= emptyToken)
  where
    rtt0OK = case resumptionSession of
      Nothing      -> False
      Just (_, sd) -> sessionMaxEarlyDataSize sd == quicMaxEarlyDataSize

-- | Is resumption possible?
isResumptionPossible :: ResumptionInfo -> Bool
isResumptionPossible ResumptionInfo{..} = isJust resumptionSession

get0RTTCipher :: ResumptionInfo -> Maybe CipherID
get0RTTCipher ri = case resumptionSession ri of
  Nothing      -> Nothing
  Just (_, sd) -> Just $ sessionCipher sd

