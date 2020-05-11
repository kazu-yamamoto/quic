{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import qualified Control.Exception as E

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Types

-- | Creating a bidirectional stream.
stream :: Connection -> IO Stream
stream conn = do
    openC <- isConnectionOpen conn
    unless openC $ E.throwIO ConnectionIsClosed
    sid <- getMyNewStreamId conn
    insertStream conn sid

-- | Creating a unidirectional stream.
unidirectionalStream :: Connection -> IO Stream
unidirectionalStream conn = do
    openC <- isConnectionOpen conn
    unless openC $ E.throwIO ConnectionIsClosed
    sid <- getMyNewUniStreamId conn
    insertStream conn sid

-- | Checking if the stream is open.
isStreamTxOpen :: Stream -> IO Bool
isStreamTxOpen s = do
    fin <- getStreamTxFin s
    return (not fin)

-- | Sending data in the stream.
sendStream :: Stream -> ByteString -> IO ()
sendStream s dat = sendStreamMany s [dat]

-- | Sending a list of data in the stream.
sendStreamMany :: Stream -> [ByteString] -> IO ()
sendStreamMany s dats = do
--    sent <- isCloseSent conn
--    when sent $ E.throwIO ConnectionIsClosed
    open <- isStreamTxOpen s
    unless open $ E.throwIO StreamIsClosed
    putOutput' (streamOutputQ s) $ OutStream s dats False

-- | Sending a FIN in the stream.
shutdownStream :: Stream -> IO ()
shutdownStream s = do
--    sent <- isCloseSent conn
--    when sent $ E.throwIO ConnectionIsClosed
    putOutput' (streamOutputQ s) $ OutStream s [] True

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
recvStream s = do
--    received <- isCloseReceived conn
--    when received $ E.throwIO ConnectionIsClosed
    takeStreamData s

isClientInitiatedBidirectional :: StreamId -> Bool
isClientInitiatedBidirectional  sid = (0b11 .&. sid) == 0

isServerInitiatedBidirectional :: StreamId -> Bool
isServerInitiatedBidirectional  sid = (0b11 .&. sid) == 1

isClientInitiatedUnidirectional :: StreamId -> Bool
isClientInitiatedUnidirectional sid = (0b11 .&. sid) == 2

isServerInitiatedUnidirectional :: StreamId -> Bool
isServerInitiatedUnidirectional sid = (0b11 .&. sid) == 3
