-- | This main module provides APIs for QUIC clients.
module Network.QUIC.Client (
  -- * Running a QUIC client
    run
  , ClientConfig(..)
  , defaultClientConfig
  -- * Certificate
  , clientCertificateChain
  -- * Hook
  , Hooks(..)
  , defaultHooks
  ) where

import Network.QUIC.Client.Run
import Network.QUIC.Config
