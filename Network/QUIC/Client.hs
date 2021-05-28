{-# LANGUAGE PatternSynonyms #-}

-- | This main module provides APIs for QUIC clients.
module Network.QUIC.Client (
  -- * Running a QUIC client
    run
  -- * Configration
  , ClientConfig
  , defaultClientConfig
  , ccServerName
  , ccPortName
  , ccALPN
  , ccUse0RTT
  , ccResumption
  , ccCiphers
  , ccGroups
  , ccParameters
  , ccCredentials
  , ccValidate -- fixme: should be True
  -- * Parameters
  , Parameters
  , defaultParameters
  -- ** Accessors
  , maxIdleTimeout
  , maxUdpPayloadSize
  , initialMaxData
  , initialMaxStreamDataBidiLocal
  , initialMaxStreamDataBidiRemote
  , initialMaxStreamDataUni
  , initialMaxStreamsBidi
  , initialMaxStreamsUni
  , ackDelayExponent
  , maxAckDelay
  , disableActiveMigration
  , activeConnectionIdLimit
  -- * Types
  , Milliseconds(..)
  -- * Resumption
  , ResumptionInfo
  , getResumptionInfo
  , isResumptionPossible
  , is0RTTPossible
  ) where

import Network.QUIC.Client.Run
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Parameters
import Network.QUIC.Types
