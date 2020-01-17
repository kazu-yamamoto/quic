{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import qualified Control.Exception as E
import qualified Data.ByteString as B

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Types

send :: Connection -> ByteString -> IO ()
send conn bs = send' conn 0 bs

send' :: Connection -> StreamID -> ByteString -> IO ()
send' conn sid bs = do
    open <- isConnectionOpen conn
    if open then do
        off <- modifyStreamOffset conn sid $ B.length bs
        putOutput conn $ OutStream sid bs off
      else
        E.throwIO ConnectionIsNotOpen

recv :: Connection -> IO ByteString
recv conn = do
    (sid, bs) <- recv' conn
    if sid == 0 then return bs else recv conn

recv' :: Connection -> IO (StreamID, ByteString)
recv' conn = do
    mi <- takeInput conn
    case mi of
      InpStream sid bs      -> return (sid, bs)
      InpApplicationError{} -> return (0, "") -- fixme sid
      InpTransportError{}   -> return (0, "") -- fixme sid
      InpHandshake{}        -> error "recv'"
