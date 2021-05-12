module Network.QUIC.Closer where

import Network.QUIC.Connection
import Network.QUIC.Types

closer :: Microseconds -> IO Int -> IO Int -> IO ()
closer pto send recv = loop (3 :: Int)
  where
    loop 0 = return ()
    loop n = do
        _ <- send
        mx <- timeout pto $ recv
        case mx of
          Nothing -> return ()
          Just 0  -> return ()
          Just _  -> loop (n - 1)
