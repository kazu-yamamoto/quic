module Network.QUIC.Closer where

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Types

closer :: Microseconds -> IO Int -> IO Int -> IO () -> IO ()
closer (Microseconds pto) send recv hook = loop (3 :: Int)
  where
    loop 0 = return ()
    loop n = do
        _ <- send
        getTimeMicrosecond >>= skip (Microseconds pto)
        mx <- timeout (Microseconds (pto .>>. 1)) $ recv
        case mx of
          Nothing -> hook
          Just 0  -> return ()
          Just _  -> loop (n - 1)
    skip tmo@(Microseconds duration) base = do
        mx <- timeout tmo recv
        case mx of
          Nothing -> return ()
          Just 0  -> return ()
          Just _  -> do
              Microseconds elapsed <- getElapsedTimeMicrosecond base
              let duration' = duration - elapsed
              when (duration' >= 5000) $ skip (Microseconds duration') base
