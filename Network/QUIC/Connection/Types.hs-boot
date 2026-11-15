module Network.QUIC.Connection.Types where

import Control.Concurrent.STM (STM)

data Connection

connectionEndSTM :: Connection -> STM a
connectionEndedSTM :: Connection -> STM ()
