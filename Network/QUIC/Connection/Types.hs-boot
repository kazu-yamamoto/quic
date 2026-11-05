module Network.QUIC.Connection.Types where

import Control.Concurrent.STM (STM)

data Connection

peerClosedSTM :: Connection -> STM a
