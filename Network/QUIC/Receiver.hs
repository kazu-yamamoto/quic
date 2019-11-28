{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Receiver (
    receiver
  ) where

import Control.Concurrent.STM
import Network.TLS.QUIC

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.TLS
import Network.QUIC.Transport
import Network.QUIC.Types

receiver :: Connection -> IO ()
receiver conn = forever $ do
    bs <- connRecv conn
    processPackets conn bs

processPackets :: Connection -> ByteString -> IO ()
processPackets conn bs0 = loop bs0
  where
    loop "" = return ()
    loop bs = do
        let level = packetEncryptionLevel bs
        checkEncryptionLevel conn level
        (pkt, rest) <- decodePacket conn bs
        processPacket conn pkt
        loop rest

processPacket :: Connection -> Packet -> IO ()
processPacket conn (InitialPacket   _ _ _ _ pn fs) = do
--    putStrLn $ "I: " ++ show fs
    rets <- mapM (processFrame conn InitialLevel) fs
    when (and rets) $ addPNs conn InitialLevel pn
processPacket conn (HandshakePacket _ _ peercid   pn fs) = do
--    putStrLn $ "H: " ++ show fs
    when (isClient conn) $ setPeerCID conn peercid
    rets <- mapM (processFrame conn HandshakeLevel) fs
    when (and rets) $ addPNs conn HandshakeLevel pn
processPacket conn (ShortPacket     _       pn fs) = do
--    putStrLn $ "S: " ++ show fs
    rets <- mapM (processFrame conn RTT1Level) fs
    when (and rets) $ addPNs conn RTT1Level pn
processPacket conn (RetryPacket ver _ sCID _ token)  = do
    -- The packet number of first crypto frame is 0.
    -- This ensures that retry can be accepted only once.
    mr <- releaseOutput conn 0
    case mr of
      Just (Retrans (OutHndClientHello0 cdat mEarydata) _ _) -> do
          -- fixme: many checking
          setPeerCID conn sCID
          setInitialSecrets conn $ initialSecrets ver sCID
          atomically $ writeTQueue (outputQ conn) $ OutHndClientHelloR cdat mEarydata token
      _ -> return ()
processPacket _ _ = undefined

processFrame :: Connection -> EncryptionLevel -> Frame -> IO Bool
processFrame _ _ Padding{} = return True
processFrame conn _ (Ack ackInfo _) = do
    let pns = fromAckInfo ackInfo
    outs <- catMaybes <$> mapM (releaseOutput conn) pns
    mapM_ (removeAcks conn) outs
    return True
processFrame conn lvl (Crypto _off cdat) = do
    --fixme _off
    case lvl of
      InitialLevel   -> do
          atomically $ writeTQueue (inputQ conn) $ InpHandshake lvl cdat emptyToken
          return True
      RTT0Level -> do
          putStrLn $  "processFrame: invalid packet type " ++ show lvl
          return False
      HandshakeLevel -> do
          atomically $ writeTQueue (inputQ conn) $ InpHandshake lvl cdat emptyToken
          return True
      RTT1Level
        | isClient conn -> do
              -- fixme: checkint key phase
              control <- getClientController conn
              RecvSessionTicket   <- control $ PutSessionTicket cdat
              ClientHandshakeDone <- control ExitClient
              clearClientController conn
              return True
        | otherwise -> do
              putStrLn "processFrame: Short:Crypto for server"
              return False
processFrame _ _ NewToken{} = do
    putStrLn "FIXME: NewToken"
    return True
processFrame _ _ (NewConnectionID sn _ _ _)  = do
    putStrLn $ "FIXME: NewConnectionID " ++ show sn
    return True
processFrame conn _ (ConnectionCloseQUIC err _ftyp _reason) = do
    atomically $ writeTQueue (inputQ conn) $ InpEerror err
    setConnectionStatus conn Closing
    setCloseReceived conn
    setCloseSent conn
    clearThreads conn
    return False
processFrame conn _ (ConnectionCloseApp err _reason) = do
    putStrLn $ "App: " ++ show err
    atomically $ writeTQueue (inputQ conn) $ InpEerror err
    setConnectionStatus conn Closing
    setCloseReceived conn
    setCloseSent conn
    clearThreads conn
    return False
processFrame conn RTT1Level (Stream sid _off dat fin) = do
    -- fixme _off
    atomically $ writeTQueue (inputQ conn) $ InpStream sid dat
    when (fin && dat /= "") $ atomically $ writeTQueue (inputQ conn) $ InpStream sid ""
    return True
processFrame _ _ _frame        = do
    -- This includes Ping which should be just acknowledged.
    putStrLn "FIXME: processFrame"
    print _frame
    return True
