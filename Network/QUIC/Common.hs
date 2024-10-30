{-# LANGUAGE StrictData #-}

module Network.QUIC.Common where

import qualified Network.Socket as NS

import Control.Concurrent
import GHC.Conc.Sync

import Network.QUIC.Connection
import Network.QUIC.Parameters
import Network.QUIC.Types

----------------------------------------------------------------

data ConnRes = ConnRes Connection AuthCIDs ~(IO ())

connResConnection :: ConnRes -> Connection
connResConnection (ConnRes conn _ _) = conn

defaultPacketSize :: NS.SockAddr -> Int
defaultPacketSize NS.SockAddrInet6{} = defaultQUICPacketSizeForIPv6
defaultPacketSize _ = defaultQUICPacketSizeForIPv4

maximumPacketSize :: NS.SockAddr -> Int
maximumPacketSize NS.SockAddrInet6{} = 1500 - 40 - 8 -- fixme
maximumPacketSize _ = 1500 - 20 - 8 -- fixme

labelMe :: String -> IO ()
labelMe name = do
    tid <- myThreadId
    mlabel <- threadLabel tid
    case mlabel of
        Nothing -> labelThread tid name
        Just _ -> return ()
