{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import qualified Control.Exception as E

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Types

-- | Checking if the stream is open.
isStreamOpen :: Connection -> StreamId -> IO Bool
isStreamOpen conn sid = do
    fin <- getStreamFin conn sid
    return (not fin)

-- | Sending data in the stream. FIN is sent if 3rd argument is 'True'.
sendStream :: Connection -> StreamId -> ByteString -> Fin -> IO ()
sendStream conn sid dat fin = do
    open <- isConnectionOpen conn
    fin0 <- getStreamFin conn sid
    if not open then
        E.throwIO ConnectionIsClosed
      else if fin0 then
        E.throwIO StreamIsClosed
      else
        putOutput conn $ OutStream sid dat fin

-- | Sending a FIN in the stream.
shutdownStream :: Connection -> StreamId -> IO ()
shutdownStream conn sid = do
    open <- isConnectionOpen conn
    if open then do
        putOutput conn $ OutShutdown sid
      else
        E.throwIO ConnectionIsClosed

-- | Receiving data in the stream. In the case where a FIN is received
--   an empty bytestring is returned. This throws 'QUICError'.
recvStream :: Connection -> IO (StreamId, ByteString, Fin)
recvStream conn = do
    mi <- takeInput conn
    case mi of
      InpStream sid bs fin    -> return (sid, bs, fin)
      InpError e              -> E.throwIO e
      InpApplicationError e r -> E.throwIO $ ApplicationErrorOccurs e r
      InpTransportError NoError _ _ -> return (0, "", True) -- fixme: 0
      InpTransportError e _ r -> E.throwIO $ TransportErrorOccurs e r
      _                       -> E.throwIO MustNotReached

isClientInitiatedBidirectional :: StreamId -> Bool
isClientInitiatedBidirectional  sid = (0b11 .&. sid) == 0

isServerInitiatedBidirectional :: StreamId -> Bool
isServerInitiatedBidirectional  sid = (0b11 .&. sid) == 1

isClientInitiatedUnidirectional :: StreamId -> Bool
isClientInitiatedUnidirectional sid = (0b11 .&. sid) == 2

isServerInitiatedUnidirectional :: StreamId -> Bool
isServerInitiatedUnidirectional sid = (0b11 .&. sid) == 3
