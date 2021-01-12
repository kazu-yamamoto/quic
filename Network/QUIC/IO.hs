{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import Control.Concurrent.STM
import qualified Control.Exception as E

import Network.QUIC.Connection
import Network.QUIC.Connector
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
    closed <- isClosed $ streamConnection s
    when closed $ E.throwIO ConnectionIsClosed
    sclosed <- isTxStreamClosed s
    when sclosed $ E.throwIO StreamIsClosed
    let len = totalLen dats
    -- fixme: size check for 0RTT
    ready <- isConnection1RTTReady $ streamConnection s
    when ready $ do
        mblocked <- isBlocked s len
        case mblocked of
          Nothing -> return ()
          Just blocked -> do
              putSendBlockedQ (streamConnection s) blocked
              waitWindowIsOpen s len
    addTxStreamData s len
    putSendStreamQ (streamConnection s) $ TxStreamData s dats len False

-- | Sending FIN in the stream.
shutdownStream :: Stream -> IO ()
shutdownStream s = do
    closed <- isClosed $ streamConnection s
    when closed $ E.throwIO ConnectionIsClosed
    sclosed <- isTxStreamClosed s
    when sclosed $ E.throwIO StreamIsClosed
    setTxStreamClosed s
    putSendStreamQ (streamConnection s) $ TxStreamData s [] 0 True

-- | Closing a stream. FIN is sent if necessary.
closeStream :: Stream -> IO ()
closeStream s = do
    closed <- isClosed $ streamConnection s
    when closed $ E.throwIO ConnectionIsClosed
    sclosed <- isTxStreamClosed s
    unless sclosed $ do
        setTxStreamClosed s
        putSendStreamQ (streamConnection s) $ TxStreamData s [] 0 True
    let conn = streamConnection s
    delStream conn s
    let sid = streamId s
    when ((isClient conn && isServerInitiatedBidirectional sid)
       || (isServer conn && isClientInitiatedBidirectional sid)) $ do
        n <- getPeerMaxStreams conn
        putOutput conn $ OutControl RTT1Level [MaxStreams Unidirectional n]

-- | Accepting a stream initiated by the peer.
acceptStream :: Connection -> IO Stream
acceptStream conn = do
    openC <- isConnectionOpen conn
    unless openC $ E.throwIO ConnectionIsClosed
    InpStream s <- takeInput conn
    return s

-- | Receiving data in the stream. In the case where a FIN is received
--   an empty bytestring is returned.
recvStream :: Stream -> Int -> IO ByteString
recvStream s n = do
    closed <- isClosed $ streamConnection s
    when closed $ E.throwIO ConnectionIsClosed
    takeRecvStreamQwithSize s n

isBlocked :: Stream -> Int -> IO (Maybe Blocked)
isBlocked s n = do
  atomically $ do
    strmFlow <- readStreamFlowTx s
    let strmWindow = flowWindow strmFlow
    connFlow <- readConnectionFlowTx $ streamConnection s
    let connWindow = flowWindow connFlow
    let blocked
         | n > strmWindow = if n > connWindow
                            then Just $ BothBlocked s (flowMaxData strmFlow) (flowMaxData connFlow)
                            else Just $ StrmBlocked s (flowMaxData strmFlow)
         | otherwise      = if n > connWindow
                            then Just $ ConnBlocked (flowMaxData connFlow)
                            else Nothing
    return blocked

waitWindowIsOpen :: Stream -> Int -> IO ()
waitWindowIsOpen s n = do
  atomically $ do
    strmWindow <- flowWindow <$> readStreamFlowTx s
    connWindow <- flowWindow <$> readConnectionFlowTx (streamConnection s)
    check (n <= strmWindow && n <= connWindow)

-- | Closing a stream with an error code.
resetStream :: Stream -> ApplicationProtocolError -> IO ()
resetStream = undefined

-- | Closing a connection with an error code.
abortConnection :: Connection -> ApplicationProtocolError -> IO ()
abortConnection = undefined
