{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import qualified Control.Exception as E

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Types

-- | Checking if the stream is open.
isStreamOpen :: Connection -> StreamID -> IO Bool
isStreamOpen conn sid = do
    open <- isConnectionOpen conn
    fin <- getStreamFin conn sid
    return (open && not fin)

-- | Sending data in stream 0.
send :: Connection -> ByteString -> IO ()
send conn dat = sendStream conn 0 False dat

-- | Sending data in the stream. 'FIN' is sent if 3rd argument is 'True'.
sendStream :: Connection -> StreamID -> Bool -> ByteString -> IO ()
sendStream conn sid fin dat = do
    open <- isConnectionOpen conn
    fin0 <- getStreamFin conn sid
    if not open then
        E.throwIO ConnectionIsClosed
      else if fin0 then
        E.throwIO StreamIsClosed
      else
        putOutput conn $ OutStream sid dat fin

-- | Sending a 'FIN' in stream 0.
shutdown :: Connection -> IO ()
shutdown conn = shutdownStream conn 0

-- | Sending a 'FIN' in the stream.
shutdownStream :: Connection -> StreamID -> IO ()
shutdownStream conn sid = do
    open <- isConnectionOpen conn
    if open then do
        putOutput conn $ OutShutdown sid
      else
        E.throwIO ConnectionIsClosed

-- | Receiving data in stream 0. In the case where a FIN is received or
--   an error occurs, an empty bytestring is returned.
recv :: Connection -> IO ByteString
recv conn = do
    mi <- takeInput conn
    case mi of
      InpStream 0   bs      -> return bs
      InpStream _   _       -> return ""
      InpFin _              -> return ""
      InpError _            -> return ""
      InpApplicationError{} -> return ""
      InpTransportError{}   -> return ""
      InpVersion{}          -> E.throwIO MustNotReached
      InpHandshake{}        -> E.throwIO MustNotReached

-- | Receiving data in the stream. In the case where a FIN is received
--   an empty bytestring is returned. This throws 'QUICError'.
recvStream :: Connection -> IO (StreamID, ByteString)
recvStream conn = do
    mi <- takeInput conn
    case mi of
      InpStream sid bs        -> return (sid, bs)
      InpFin sid              -> return (sid, "")
      InpError e              -> E.throwIO e
      InpApplicationError e r -> E.throwIO $ ApplicationErrorOccurs e r
      InpTransportError e _ r -> E.throwIO $ TransportErrorOccurs e r
      _                       -> E.throwIO MustNotReached
