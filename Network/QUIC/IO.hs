{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import qualified Control.Exception as E
import qualified Data.ByteString as B

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Types

send :: Connection -> ByteString -> IO ()
send conn dat = sendStream conn 0 False dat

sendStream :: Connection -> StreamID -> Bool -> ByteString -> IO ()
sendStream conn sid fin dat = do
    open <- isConnectionOpen conn
    if open then do
        off <- modifyStreamOffset conn sid $ B.length dat
        putOutput conn $ OutStream sid dat off fin
      else
        E.throwIO ConnectionIsNotOpen

shutdown :: Connection -> IO ()
shutdown conn = shutdownStream conn 0

shutdownStream :: Connection -> StreamID -> IO ()
shutdownStream conn sid = do
    open <- isConnectionOpen conn
    if open then do
        off <- modifyStreamOffset conn sid 0
        putOutput conn $ OutStream sid "" off True
      else
        E.throwIO ConnectionIsNotOpen

recv :: Connection -> IO ByteString
recv conn = do
    mi <- takeInput conn
    case mi of
      InpStream 0   bs      -> return bs
      InpStream _   _       -> return ""
      InpApplicationError{} -> return ""
      InpTransportError{}   -> return ""
      InpVersion{}          -> error "recvStream"
      InpHandshake{}        -> error "recvStream"

recvStream :: Connection -> IO (StreamID, ByteString)
recvStream conn = do
    mi <- takeInput conn
    case mi of
      InpStream sid bs        -> return (sid, bs)
      InpApplicationError e r -> E.throwIO $ ApplicationErrorOccurs e r
      InpTransportError e _ r -> E.throwIO $ TransportErrorOccurs e r
      _                       -> E.throwIO MustNotReached
