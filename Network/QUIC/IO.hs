{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.IO where

import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as BS

import Network.QUIC.Connection
import Network.QUIC.Connector
import Network.QUIC.Imports
import Network.QUIC.Stream
import Network.QUIC.Types

-- | Creating a bidirectional stream.
stream :: Connection -> IO Stream
stream conn = do
    sid <- getMyNewStreamId conn
    addStream conn sid

-- | Creating a unidirectional stream.
unidirectionalStream :: Connection -> IO Stream
unidirectionalStream conn = do
    sid <- getMyNewUniStreamId conn
    addStream conn sid

-- | Sending data in the stream.
sendStream :: Stream -> ByteString -> IO ()
sendStream s dat = sendStreamMany s [dat]

----------------------------------------------------------------

-- | Sending a list of data in the stream.
sendStreamMany :: Stream -> [ByteString] -> IO ()
sendStreamMany _   [] = return ()
sendStreamMany s dats0 = do
    sclosed <- isTxStreamClosed s
    when sclosed $ E.throwIO StreamIsClosed
    -- fixme: size check for 0RTT
    ready <- isConnection1RTTReady conn
    if not ready then do
        -- 0-RTT
        let len = totalLen dats0
        atomically $ do
            addTxStreamData s len
            addTxData conn len
        putSendStreamQ conn $ TxStreamData s dats0 len False
      else
        flowControl dats0
  where
    conn = streamConnection s
    flowControl dats = do
        -- 1-RTT
        let len = totalLen dats
        eblocked <- isBlocked s len
        case eblocked of
          Right n
            | len == n  ->
                  putSendStreamQ conn $ TxStreamData s dats len False
            | otherwise -> do
                  let (dats1,dats2) = split n dats
                  putSendStreamQ conn $ TxStreamData s dats1 n False
                  flowControl dats2
          Left blocked  -> do
              putSendBlockedQ conn blocked
              waitWindowIsOpen s len
              putSendStreamQ conn $ TxStreamData s dats len False

split :: Int -> [BS.ByteString] -> ([BS.ByteString],[BS.ByteString])
split n0 dats0 = loop n0 dats0 id
  where
    loop 0 bss      build = (build [], bss)
    loop _ []       build = (build [], [])
    loop n (bs:bss) build = case len `compare` n of
        GT -> let (bs1,bs2) = BS.splitAt n bs
              in (build [bs1], bs2:bss)
        EQ -> (build [bs], bss)
        LT -> loop (n - len) bss (build . (bs :))
      where
        len = BS.length bs

isBlocked :: Stream -> Int -> IO (Either Blocked Int)
isBlocked s len = atomically $ do
    let conn = streamConnection s
    strmFlow <- readStreamFlowTx s
    connFlow <- readConnectionFlowTx conn
    let strmWindow = flowWindow strmFlow
        connWindow = flowWindow connFlow
        minFlow = min strmWindow connWindow
        n = min len minFlow
    if n > 0 then do
        addTxStreamData s n
        addTxData conn n
        return $ Right n
      else do
        let cs = len > strmWindow
            cw = len > connWindow
            blocked
              | cs && cw  = BothBlocked s (flowMaxData strmFlow) (flowMaxData connFlow)
              | cs        = StrmBlocked s (flowMaxData strmFlow)
              | otherwise = ConnBlocked (flowMaxData connFlow)
        return $ Left blocked

waitWindowIsOpen :: Stream -> Int -> IO ()
waitWindowIsOpen s len = atomically $ do
    let conn = streamConnection s
    strmWindow <- flowWindow <$> readStreamFlowTx s
    connWindow <- flowWindow <$> readConnectionFlowTx conn
    check (len <= strmWindow && len <= connWindow)
    addTxStreamData s len
    addTxData conn len

----------------------------------------------------------------

-- | Sending FIN in the stream.
shutdownStream :: Stream -> IO ()
shutdownStream s = do
    sclosed <- isTxStreamClosed s
    when sclosed $ E.throwIO StreamIsClosed
    setTxStreamClosed s
    putSendStreamQ (streamConnection s) $ TxStreamData s [] 0 True

-- | Closing a stream. FIN is sent if necessary.
closeStream :: Stream -> IO ()
closeStream s = do
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
        putOutput conn $ OutControl RTT1Level [MaxStreams Unidirectional n] False

-- | Accepting a stream initiated by the peer.
acceptStream :: Connection -> IO Stream
acceptStream conn = do
    InpStream s <- takeInput conn
    return s

-- | Receiving data in the stream. In the case where a FIN is received
--   an empty bytestring is returned.
recvStream :: Stream -> Int -> IO ByteString
recvStream s n = takeRecvStreamQwithSize s n

-- | Closing a stream with an error code.
resetStream :: Stream -> ApplicationProtocolError -> IO ()
resetStream s aerr = do
    let conn = streamConnection s
    lvl <- getEncryptionLevel conn
    putOutput conn $ OutControl lvl [frame] False
    -- fixme: some operations are necessary here.
  where
    frame = ResetStream (streamId s) aerr 0
