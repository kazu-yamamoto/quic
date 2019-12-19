{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as B

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Types

sendData :: Connection -> ByteString -> IO ()
sendData conn bs = sendData' conn 0 bs

sendData' :: Connection -> StreamID -> ByteString -> IO ()
sendData' conn sid bs = do
    open <- isConnectionOpen conn
    if open then do
        off <- modifyStreamOffset conn sid $ B.length bs
        atomically $ writeTQueue (outputQ conn) $ OutStream sid bs off
      else
        E.throwIO ConnectionIsNotOpen

recvData :: Connection -> IO ByteString
recvData conn = do
    (sid, bs) <- recvData' conn
    if sid == 0 then return bs else recvData conn

recvData' :: Connection -> IO (StreamID, ByteString)
recvData' conn = do
    mi <- atomically $ readTQueue (inputQ conn)
    case mi of
      InpStream sid bs      -> return (sid, bs)
      InpApplicationError{} -> return (0, "") -- fixme sid
      InpTransportError{}   -> return (0, "") -- fixme sid
      InpHandshake{}        -> error "recvData'"
