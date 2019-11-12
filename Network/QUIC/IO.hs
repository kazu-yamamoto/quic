module Network.QUIC.IO where

import qualified Control.Exception as E
import Control.Concurrent.STM

import Network.QUIC.Context
import Network.QUIC.Imports
import Network.QUIC.Transport.Types

sendData :: Context -> ByteString -> IO ()
sendData ctx bs = sendData' ctx 0 bs

sendData' :: Context -> StreamID -> ByteString -> IO ()
sendData' ctx sid bs = do
    open <- isConnectionOpen ctx
    if open then
        atomically $ writeTQueue (outputQ ctx) $ S sid bs
      else
        E.throwIO ConnectionIsNotOpen

recvData :: Context -> IO ByteString
recvData ctx = do
    (sid, bs) <- recvData' ctx
    if sid == 0 then return bs else recvData ctx

recvData' :: Context -> IO (StreamID, ByteString)
recvData' ctx = do
    S sid bs <- atomically $ readTQueue (inputQ ctx)
    return (sid, bs)
