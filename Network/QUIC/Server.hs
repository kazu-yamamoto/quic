{-# LANGUAGE PatternSynonyms #-}

-- | This main module provides APIs for QUIC servers.
module Network.QUIC.Server (
  -- * Running a QUIC server
    run
  , ServerConfig(..)
  , defaultServerConfig
  , stop
  -- * Hook
  , Hooks(..)
  , defaultHooks
  ) where

import Network.QUIC.Config
import Network.QUIC.Server.Run
