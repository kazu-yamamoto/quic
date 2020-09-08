{-# LANGUAGE CPP #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

#include <sys/types.h>
#include <sys/socket.h>

module Network.QUIC.Recovery.Pace (
    setPace
  ) where

#ifdef SO_MAX_PACING_RATE
import Control.Concurrent.STM
import Foreign.C.Types
import qualified Network.Socket as NS

import Network.QUIC.Imports
import Network.QUIC.Recovery.Misc
import Network.QUIC.Types
#endif

import Network.QUIC.Recovery.Types

setPace :: LDCC -> IO ()
#ifdef SO_MAX_PACING_RATE
setPace ldcc@LDCC{..} = do
        CC{congestionWindow} <- readTVarIO recoveryCC
        RTT{smoothedRTT} <- readIORef recoveryRTT
        let Microseconds srtt = smoothedRTT
            pace0 = congestionWindow * 1000 * 1000 `div` srtt
            pace1 = pace0 + (pace0 .>>. 2)
            pace2 = fromIntegral pace1 :: CInt
            pace  = max (1024 * 1024) pace2
        s <- getSocket ldcc
        NS.setSockOpt s (NS.SockOpt (#const SOL_SOCKET) (#const SO_MAX_PACING_RATE)) pace
#else
setPace _ = return ()
#endif
