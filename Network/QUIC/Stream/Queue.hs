{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Queue where

import Data.ByteString (ByteString)
import UnliftIO.STM

import Network.QUIC.Stream.Types

putRecvStreamQ :: Stream -> ByteString -> IO ()
putRecvStreamQ Stream{..} = atomically . writeTQueue (recvStreamQ streamRecvQ)

takeRecvStreamQ :: Stream -> IO ByteString
takeRecvStreamQ Stream{..} = atomically $ readTQueue $ recvStreamQ streamRecvQ

tryTakeRecvStreamQ :: Stream -> IO (Maybe ByteString)
tryTakeRecvStreamQ Stream{..} = atomically $ tryReadTQueue $ recvStreamQ streamRecvQ
