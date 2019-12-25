module Network.QUIC.Types.Resumption where

import Network.TLS

import Network.QUIC.Types.Frame

type SessionEstablish = SessionID -> SessionData -> IO ()

data ResumptionInfo = ResumptionInfo {
    resumptionSession :: Maybe (SessionID, SessionData)
  , resumptionToken   :: Token
  } deriving (Eq, Show)

defaultResumptionInfo :: ResumptionInfo
defaultResumptionInfo = ResumptionInfo {
    resumptionSession = Nothing
  , resumptionToken   = emptyToken
  }

is0RTTPossible :: ResumptionInfo -> Bool
is0RTTPossible ri = case resumptionSession ri of
  Nothing      -> False
  Just (_, sd) -> sessionMaxEarlyDataSize sd == 0xffffffff

isResumptionPossible :: ResumptionInfo -> Bool
isResumptionPossible ri = case resumptionSession ri of
  Nothing      -> False
  _            -> True

get0RTTCipher :: ResumptionInfo -> Maybe CipherID
get0RTTCipher ri = case resumptionSession ri of
  Nothing      -> Nothing
  Just (_, sd) -> Just $ sessionCipher sd

