{-# LANGUAGE OverloadedStrings #-}

module Network.QUIC.Receiver where

import Control.Concurrent
import Control.Concurrent.STM
import Network.TLS.QUIC

import Network.QUIC.Connection
import Network.QUIC.Imports
import Network.QUIC.Transport

receiver :: Connection -> IO ()
receiver conn = do
    mbs <- readClearClientInitial conn
    case mbs of
        Nothing -> loop
        Just bs -> do
            processPackets conn bs
            loop
  where
    loop = forever $ do
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
      addPNs conn Initial pn
--      putStrLn $ "I: " ++ show fs
      mapM_ (processFrame conn Initial) fs
processPacket conn (HandshakePacket _ _ peercid   pn fs) = do
      addPNs conn Handshake pn
--      putStrLn $ "H: " ++ show fs
      when (isClient conn) $ setPeerCID conn peercid
      mapM_ (processFrame conn Handshake) fs
processPacket conn (ShortPacket     _       pn fs) = do
      addPNs conn Short pn
--      putStrLn $ "S: " ++ show fs
      mapM_ (processFrame conn Short) fs
processPacket _conn RetryPacket{}  = undefined -- fixme
processPacket _ _ = undefined

processFrame :: Connection -> PacketType -> Frame -> IO ()
processFrame _ _ Padding = return ()
processFrame _ _ Ack{} = return ()
processFrame conn pt (Crypto _off cdat) = do
    --fixme _off
    case pt of
      Initial   -> atomically $ writeTQueue (inputQ conn) $ H pt cdat
      Handshake -> atomically $ writeTQueue (inputQ conn) $ H pt cdat
      Short     -> when (isClient conn) $ do
          -- fixme: checkint key phase
          control <- tlsClientController conn
          RecvSessionTicket <- control $ PutSessionTicket cdat
          ClientHandshakeDone <- control ExitClient
          clearController conn
      _         -> error "processFrame"
processFrame _ _ NewToken{} =
    putStrLn "FIXME: NewToken"
processFrame _ _ (NewConnectionID sn _ _ _)  =
    putStrLn $ "FIXME: NewConnectionID " ++ show sn
processFrame conn pt (ConnectionCloseQUIC err _ftyp _reason) = do
    case pt of
      Initial   -> atomically $ writeTQueue (inputQ conn) $ E err
      Handshake -> atomically $ writeTQueue (inputQ conn) $ E err
      _         -> return ()
    setConnectionStatus conn Closing
    setCloseReceived conn
    sent <- isCloseSent conn
    let frames
          | sent      = [] -- for acking
          | otherwise = [ConnectionCloseApp NoError ""]
    setCloseSent conn
    atomically $ writeTQueue (outputQ conn) $ C pt frames
    threadDelay 100000 -- fixme
processFrame conn pt (ConnectionCloseApp err _reason) = do
    putStrLn $ "App: " ++ show err
    setConnectionStatus conn Closing
    setCloseReceived conn
    sent <- isCloseSent conn
    let frames
          | sent      = [] -- for acking
          | otherwise = [ConnectionCloseApp NoError ""]
    setCloseSent conn
    atomically $ writeTQueue (outputQ conn) $ C pt frames
    threadDelay 100000 -- fixme
processFrame conn Short (Stream sid _off dat fin) = do
    -- fixme _off
    atomically $ writeTQueue (inputQ conn) $ S sid dat
    when (fin && dat /= "") $ atomically $ writeTQueue (inputQ conn) $ S sid ""
processFrame _ _ _frame        = do
    putStrLn "FIXME: processFrame"
    print _frame
