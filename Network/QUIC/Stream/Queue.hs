{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Queue where

import Control.Concurrent.STM
import Data.ByteString (ByteString)

import Network.QUIC.Stream.Types

putRecvStreamQ :: Stream -> ByteString -> IO ()
putRecvStreamQ Stream{..} = atomically . writeTQueue (recvStreamQ streamRecvQ)

takeRecvStreamQ :: Stream -> IO ByteString
takeRecvStreamQ Stream{..} = atomically $ readTQueue $ recvStreamQ streamRecvQ

tryTakeRecvStreamQ :: Stream -> IO (Maybe ByteString)
tryTakeRecvStreamQ Stream{..} = atomically $ tryReadTQueue $ recvStreamQ streamRecvQ
