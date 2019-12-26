{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Types.Resumption where

import Network.TLS

import Network.QUIC.Imports
import Network.QUIC.Types.Frame

type SessionEstablish = SessionID -> SessionData -> IO ()

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

is0RTTPossible :: ResumptionInfo -> Bool
is0RTTPossible ResumptionInfo{..} =
    rtt0OK && (not resumptionRetry || resumptionToken /= emptyToken)
  where
    rtt0OK = case resumptionSession of
      Nothing      -> False
      Just (_, sd) -> sessionMaxEarlyDataSize sd == 0xffffffff

isResumptionPossible :: ResumptionInfo -> Bool
isResumptionPossible ResumptionInfo{..} = isJust resumptionSession

get0RTTCipher :: ResumptionInfo -> Maybe CipherID
get0RTTCipher ri = case resumptionSession ri of
  Nothing      -> Nothing
  Just (_, sd) -> Just $ sessionCipher sd

