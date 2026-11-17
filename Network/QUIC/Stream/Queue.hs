{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Stream.Queue where

import Control.Concurrent.STM
import Control.Monad (unless, void)
import Data.ByteString (ByteString)
import Data.Maybe (isJust)

import {-# SOURCE #-} Network.QUIC.Connection.Types (
    waitFinishedSTM,
    connectionEndedSTM,
 )
import Network.QUIC.Stream.Types

putRecvStreamQ :: Stream -> ByteString -> IO ()
putRecvStreamQ Stream{..} = atomically . writeTQueue (recvStreamQ streamRecvQ)

takeRecvStreamQ :: Stream -> IO ByteString
takeRecvStreamQ Stream{..} =
    atomically $
        readTQueue (recvStreamQ streamRecvQ) `orElse` waitFinishedSTM streamConnection

-- | Waiting until 'Network.QUIC.recvStream' would not block: something
--   is pending from a read before, the end of the stream has been read,
--   something is in the queue (data, a FIN or a reset), or the connection
--   has ended.
--
--   @since 0.4.0
waitReadableSTM :: Stream -> STM ()
waitReadableSTM Stream{..} = do
    eos <- readTVar $ endOfStream streamRecvQ
    pending <- readTVar $ pendingData streamRecvQ
    unless (eos || isJust pending) $
        void (peekTQueue $ recvStreamQ streamRecvQ)
            `orElse` connectionEndedSTM streamConnection

tryTakeRecvStreamQ :: Stream -> IO (Maybe ByteString)
tryTakeRecvStreamQ Stream{..} = atomically $ tryReadTQueue $ recvStreamQ streamRecvQ
