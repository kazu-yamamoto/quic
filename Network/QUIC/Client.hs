-- | This main module provides APIs for QUIC clients.
--   When a new better network interface is up,
--   migration is done automatically.
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
--  , ccCredentials
  , ccValidate
  , ccAutoMigration
  -- * Resumption
  , ResumptionInfo
  , getResumptionInfo
  , isResumptionPossible
  , is0RTTPossible
  -- * Migration
  , migrate
  ) where

import Network.QUIC.Client.Run
import Network.QUIC.Config
import Network.QUIC.Connection
import Network.QUIC.Types
