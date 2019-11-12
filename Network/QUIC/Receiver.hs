{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.QUIC.Receiver where

import Control.Concurrent
import Control.Concurrent.STM
import Network.TLS.QUIC

import Network.QUIC.Context
import Network.QUIC.Imports
import Network.QUIC.Transport

receiver :: Context -> IO ()
receiver ctx = do
    mbs <- readClearClientInitial ctx
    case mbs of
        Nothing -> loop
        Just bs -> do
            processPackets ctx bs
            loop
  where
    loop = forever $ do
        bs <- ctxRecv ctx
        processPackets ctx bs

processPackets :: Context -> ByteString -> IO ()
processPackets ctx bs0 = loop bs0
  where
    loop "" = return ()
    loop bs = do
        let level = packetEncryptionLevel bs
        checkEncryptionLevel ctx level
        (pkt, rest) <- decodePacket ctx bs
        processPacket ctx pkt
        loop rest

processPacket :: Context -> Packet -> IO ()
processPacket ctx (InitialPacket   _ _ _ _ pn fs) = do
      addPNs ctx Initial pn
--      putStrLn $ "I: " ++ show fs
      mapM_ (processFrame ctx Initial) fs
processPacket ctx (HandshakePacket _ _ peercid   pn fs) = do
      addPNs ctx Handshake pn
--      putStrLn $ "H: " ++ show fs
      when (isClient ctx) $ setPeerCID ctx peercid
      mapM_ (processFrame ctx Handshake) fs
processPacket ctx (ShortPacket     _       pn fs) = do
      addPNs ctx Short pn
--      putStrLn $ "S: " ++ show fs
      mapM_ (processFrame ctx Short) fs
processPacket _ _ = undefined

processFrame :: Context -> PacketType -> Frame -> IO ()
processFrame _ _ Padding = return ()
processFrame _ _ Ack{} = return ()
processFrame ctx pt (Crypto _off cdat) = do
    --fixme _off
    case pt of
      Initial   -> atomically $ writeTQueue (inputQ ctx) $ H pt cdat
      Handshake -> atomically $ writeTQueue (inputQ ctx) $ H pt cdat
      Short     -> when (isClient ctx) $ do
          -- fixme: checkint key phase
          control <- tlsClientController ctx
          RecvSessionTicket <- control $ PutSessionTicket cdat
          ClientHandshakeDone <- control ExitClient
          clearController ctx
      _         -> error "processFrame"
processFrame _ _ NewToken{} =
    putStrLn "FIXME: NewToken"
processFrame _ _ NewConnectionID{} =
    putStrLn "FIXME: NewConnectionID"
processFrame ctx pt (ConnectionCloseQUIC err _ftyp _reason) = do
    putStrLn $ "QUIC: " ++ show err
    setConnectionStatus ctx Closing
    setCloseReceived ctx
    sent <- isCloseSent ctx
    let frames
          | sent      = [] -- for acking
          | otherwise = [ConnectionCloseApp NoError ""]
    setCloseSent ctx
    atomically $ writeTQueue (outputQ ctx) $ C pt frames
    threadDelay 100000 -- fixme
processFrame ctx pt (ConnectionCloseApp err _reason) = do
    putStrLn $ "App: " ++ show err
    setConnectionStatus ctx Closing
    setCloseReceived ctx
    sent <- isCloseSent ctx
    let frames
          | sent      = [] -- for acking
          | otherwise = [ConnectionCloseApp NoError ""]
    setCloseSent ctx
    atomically $ writeTQueue (outputQ ctx) $ C pt frames
    threadDelay 100000 -- fixme
processFrame ctx Short (Stream sid _off dat fin) = do
    -- fixme _off
    atomically $ writeTQueue (inputQ ctx) $ S sid dat
    when (fin && dat /= "") $ atomically $ writeTQueue (inputQ ctx) $ S sid ""
processFrame _ _ _frame        = do
    putStrLn "FIXME: processFrame"
    print _frame
