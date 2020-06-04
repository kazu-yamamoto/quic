{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Queue where

import Data.ByteString (ByteString)
import Control.Concurrent.STM

import Network.QUIC.Stream.Types

putRecvStreamQ :: Stream -> ByteString -> IO ()
putRecvStreamQ Stream{..} = atomically . writeTQueue (recvStreamQ streamRecvQ)

takeRecvStreamQ :: Stream -> IO ByteString
takeRecvStreamQ Stream{..} = atomically $ readTQueue $ recvStreamQ streamRecvQ

tryTakeRecvStreamQ :: Stream -> IO (Maybe ByteString)
tryTakeRecvStreamQ Stream{..} = atomically $ tryReadTQueue $ recvStreamQ streamRecvQ

----------------------------------------------------------------

takeSendStreamQ :: Stream -> IO TxStreamData
takeSendStreamQ strm = atomically $ readTBQueue $ sharedSendStreamQ $ streamShared strm

tryPeekSendStreamQ :: Stream -> IO (Maybe TxStreamData)
tryPeekSendStreamQ strm = atomically $ tryPeekTBQueue $ sharedSendStreamQ $ streamShared strm

putSendStreamQ :: Stream -> TxStreamData -> IO ()
putSendStreamQ strm out = atomically $ writeTBQueue (sharedSendStreamQ $ streamShared strm) out
