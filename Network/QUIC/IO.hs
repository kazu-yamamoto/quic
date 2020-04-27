{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import qualified Control.Exception as E

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Types

stream :: Connection -> IO Stream
stream conn = do
    sid <- getMyNewStreamId conn
    insertStream conn sid

unidirectionalStream :: Connection -> IO Stream
unidirectionalStream conn = do
    sid <- getMyNewUniStreamId conn
    insertStream conn sid

-- | Checking if the stream is open.
isStreamOpen :: Stream -> IO Bool
isStreamOpen s = do
    fin <- getStreamFin s
    return (not fin)

-- | Sending data in the stream. FIN is sent if 3rd argument is 'True'.
sendStream :: Stream -> ByteString -> Fin -> IO ()
sendStream s dat fin = do
    let conn = streamConnection s
    open <- isConnectionOpen conn
    fin0 <- getStreamFin s
    if not open then
        E.throwIO ConnectionIsClosed
      else if fin0 then
        E.throwIO StreamIsClosed
      else
        putOutput conn $ OutStream s [dat] fin

-- | Sending a list of data in the stream. FIN is sent if 3rd argument is 'True'.
sendStreamMany :: Connection -> Stream -> [ByteString] -> Fin -> IO ()
sendStreamMany conn s dats fin = do
    open <- isConnectionOpen conn
    fin0 <- getStreamFin s
    if not open then
        E.throwIO ConnectionIsClosed
      else if fin0 then
        E.throwIO StreamIsClosed
      else
        putOutput conn $ OutStream s dats fin

-- | Sending a FIN in the stream.
shutdownStream :: Stream -> IO ()
shutdownStream s = do
    let conn = streamConnection s
    open <- isConnectionOpen conn
    if open then do
        putOutput conn $ OutShutdown s
      else
        E.throwIO ConnectionIsClosed

-- | Receiving data in the stream. In the case where a FIN is received
--   an empty bytestring is returned. This throws 'QUICError'.
acceptStream :: Connection -> IO (Either QUICError Stream)
acceptStream conn = do
    mi <- takeInput conn
    case mi of
      InpNewStream s          -> return $ Right s
      InpError e              -> return $ Left e
      InpApplicationError e r -> return $ Left $ ApplicationErrorOccurs e r
      InpTransportError NoError _ _ -> return $ Left ConnectionIsClosed
      InpTransportError e _ r -> return $ Left $ TransportErrorOccurs e r
      _                       -> E.throwIO MustNotReached

-- | Receiving data in the stream. In the case where a FIN is received
--   an empty bytestring is returned. This throws 'QUICError'.
recvStream :: Stream -> IO (ByteString, Fin)
recvStream = takeStreamData

isClientInitiatedBidirectional :: StreamId -> Bool
isClientInitiatedBidirectional  sid = (0b11 .&. sid) == 0

isServerInitiatedBidirectional :: StreamId -> Bool
isServerInitiatedBidirectional  sid = (0b11 .&. sid) == 1

isClientInitiatedUnidirectional :: StreamId -> Bool
isClientInitiatedUnidirectional sid = (0b11 .&. sid) == 2

isServerInitiatedUnidirectional :: StreamId -> Bool
isServerInitiatedUnidirectional sid = (0b11 .&. sid) == 3
