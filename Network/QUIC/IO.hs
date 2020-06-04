{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import qualified Control.Exception as E
import qualified Data.ByteString as B

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Stream
import Network.QUIC.Types

-- | Creating a bidirectional stream.
stream :: Connection -> IO Stream
stream conn = do
    openC <- isConnectionOpen conn
    unless openC $ E.throwIO ConnectionIsClosed
    sid <- getMyNewStreamId conn
    addStream conn sid

-- | Creating a unidirectional stream.
unidirectionalStream :: Connection -> IO Stream
unidirectionalStream conn = do
    openC <- isConnectionOpen conn
    unless openC $ E.throwIO ConnectionIsClosed
    sid <- getMyNewUniStreamId conn
    addStream conn sid

-- | Sending data in the stream.
sendStream :: Stream -> ByteString -> IO ()
sendStream s dat = sendStreamMany s [dat]

-- | Sending a list of data in the stream.
sendStreamMany :: Stream -> [ByteString] -> IO ()
sendStreamMany s dats = do
    closed <- isTxClosed s
    when closed $ E.throwIO ConnectionIsClosed
    sclosed <- isTxStreamClosed s
    when sclosed $ E.throwIO StreamIsClosed
    let len = sum $ map B.length dats
    -- fixme: size check for 0RTT
    ready <- get1RTTReady s
    when ready $ waitWindowIsOpen s len
    addTxStreamData s len
    putTxStreamData s $ TxStreamData s dats len False

-- | Sending a FIN in the stream.
shutdownStream :: Stream -> IO ()
shutdownStream s = do
    closed <- isTxClosed s
    when closed $ E.throwIO ConnectionIsClosed
    sclosed <- isTxStreamClosed s
    when sclosed $ E.throwIO StreamIsClosed
    putTxStreamData s $ TxStreamData s [] 0 True

-- | Accepting a stream initiated by the peer.
acceptStream :: Connection -> IO (Either QUICError Stream)
acceptStream conn = do
    openC <- isConnectionOpen conn
    unless openC $ E.throwIO ConnectionIsClosed
    mi <- takeInput conn
    case mi of
      InpNewStream        s         -> return $ Right s
      InpError e                    -> return $ Left e
      InpApplicationError e r       -> return $ Left $ ApplicationErrorOccurs e r
      InpTransportError NoError _ _ -> return $ Left ConnectionIsClosed
      InpTransportError e _ r       -> return $ Left $ TransportErrorOccurs e r
      _                             -> E.throwIO MustNotReached

-- | Receiving data in the stream. In the case where a FIN is received
--   an empty bytestring is returned.
recvStream :: Stream -> Int -> IO ByteString
recvStream s n = do
    closed <- isRxClosed s
    when closed $ E.throwIO ConnectionIsClosed
    takeRxStreamData s n
