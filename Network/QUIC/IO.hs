module Network.QUIC.IO where

import qualified Control.Exception as E
import Control.Concurrent.STM

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Transport.Types

sendData :: Connection -> ByteString -> IO ()
sendData conn bs = sendData' conn 0 bs

sendData' :: Connection -> StreamID -> ByteString -> IO ()
sendData' conn sid bs = do
    open <- isConnectionOpen conn
    if open then
        atomically $ writeTQueue (outputQ conn) $ S sid bs
      else
        E.throwIO ConnectionIsNotOpen

recvData :: Connection -> IO ByteString
recvData conn = do
    (sid, bs) <- recvData' conn
    if sid == 0 then return bs else recvData conn

recvData' :: Connection -> IO (StreamID, ByteString)
recvData' conn = do
    S sid bs <- atomically $ readTQueue (inputQ conn)
    return (sid, bs)
